import * as core from '@actions/core'
import * as exec from '@actions/exec'
import * as cache from '@actions/tool-cache'

import stream from 'stream'
const GRYPE_VERSION = 'v0.74.5'
const grypeBinary = 'grype'
const grypeVersion = GRYPE_VERSION
export interface IVulnerability {
  id: string
  severity: string
  dataSource: string
  links: string[]
  description: string
  fixedInVersion?: string
  cvss?: {
    source: string
    type: string
    version: string
    vector: string
    metrics?: {
      baseScore: number
      exploitabilityScore: number
      impactScore: number
    }
    vendorMetadata: { [id: string]: string }
  }[]
  fix?: {
    versions: string[]
    state: string
  }
}
export interface IGrypeFinding {
  vulnerability: IVulnerability
  artifact: IArtifact
  relatedVulnerabilities: IVulnerability[]
}
export interface IArtifact {
  id?: string
  name: string
  version: string
  type: string
  foundBy: string[]
  locations: string[] // note: only dir scans are supported, not image scans
}
export function getResultsDiff(
  head: IGrypeFinding[],
  base: IGrypeFinding[]
): IGrypeFinding[] {
  const results: IGrypeFinding[] = []
  for (const headItem of head) {
    const baseItem = base.find(
      (item: IGrypeFinding) =>
        item.artifact.name === headItem.artifact.name &&
        item.artifact.version === headItem.artifact.version &&
        item.vulnerability.id === headItem.vulnerability.id
    )
    if (!baseItem) {
      results.push(headItem)
    }
  }
  return results
}
export function mapToReport(
  results: IGrypeFinding[]
): { [key: string]: string | undefined }[] {
  return results.map(result => {
    return {
      CVE: result.vulnerability.id,
      'Package Name': result.artifact.name,
      'Package Version': result.artifact.version,
      Ecosystem: result.artifact.type,
      Source: result.vulnerability.dataSource,
      Severity: result.vulnerability.severity,
      CVSS: result.vulnerability.cvss
        ?.map(cvss => cvss.metrics?.baseScore)
        .join(','),
      Description: result.vulnerability.description,
      'Related Vulnerabilities': result.relatedVulnerabilities
        .map(vuln => vuln.id)
        .join(','),
      'Fix Versions': result.vulnerability.fix?.versions.join(',')
    }
  })
}
async function downloadGrype(version = grypeVersion): Promise<string> {
  const url = `https://raw.githubusercontent.com/anchore/grype/main/install.sh`

  core.debug(`Installing ${version}`)

  // TODO: when grype starts supporting unreleased versions, support it here
  // Download the installer, and run
  const installPath = await cache.downloadTool(url)
  // Make sure the tool's executable bit is set
  await exec.exec(`chmod +x ${installPath}`)

  const cmd = `${installPath} -b ${installPath}_grype ${version}`
  await exec.exec(cmd)
  const grypePath = `${installPath}_grype/grype`

  // Cache the downloaded file
  return cache.cacheFile(grypePath, `grype`, `grype`, version)
}

async function installGrype(version = grypeVersion): Promise<string> {
  let grypePath = cache.find(grypeBinary, version)
  if (!grypePath) {
    // Not found, install it
    grypePath = await downloadGrype(version)
  }

  // Add tool to path for this and future actions to use
  core.addPath(grypePath)
  return `${grypePath}/${grypeBinary}`
}

// Determines if multiple arguments are defined
export function multipleDefined(...args: string[]): boolean {
  let defined = false
  for (const a of args) {
    if (defined && a) {
      return true
    }
    if (a) {
      defined = true
    }
  }
  return false
}

export function sourceInput(): { head: string; base?: string } {
  // var image = core.getInput("image");
  let path = core.getInput('path')
  const basePath = core.getInput('base-path')
  // var sbom = core.getInput("sbom");

  // if (multipleDefined(image, path, sbom)) {
  //   throw new Error(
  //     "The following options are mutually exclusive: image, path, sbom"
  //   );
  // }

  // if (image) {
  //   return image;
  // }

  // if (sbom) {
  //   return "sbom:" + sbom;
  // }

  if (!path) {
    // Default to the CWD
    path = '.'
  }
  if (basePath) {
    return { head: `dir:${path}`, base: `dir:${basePath}` }
  }
  return { head: `dir:${path}` }
}

/**
 * Wait for a number of milliseconds. Resolves with 'done!' after the wait time.
 */
export async function runScan({
  source,
  failBuild,
  severityCutoff,
  onlyFixed,
  outputFormat,
  addCpesIfNone,
  byCve,
  vex
}: {
  source: string
  failBuild: string
  severityCutoff: string
  onlyFixed: string
  outputFormat: string
  addCpesIfNone: string
  byCve: string
  vex?: string
}): Promise<{
  sarif?: string
  json?: IGrypeFinding[]
}> {
  const out: {
    sarif?: string
    json?: IGrypeFinding[]
  } = {}

  const env = {
    ...process.env,
    GRYPE_CHECK_FOR_APP_UPDATE: 'true'
  }

  const SEVERITY_LIST = ['negligible', 'low', 'medium', 'high', 'critical']
  const FORMAT_LIST = ['sarif', 'json', 'table']
  const cmdArgs: string[] = []

  if (core.isDebug()) {
    cmdArgs.push(`-vv`)
  }

  const parsedOnlyFixed = onlyFixed.toLowerCase() === 'true'
  const parsedAddCpesIfNone = addCpesIfNone.toLowerCase() === 'true'
  const parsedByCve = byCve.toLowerCase() === 'true'

  cmdArgs.push('-o', outputFormat)

  if (
    !SEVERITY_LIST.some(
      item =>
        typeof severityCutoff.toLowerCase() === 'string' &&
        item === severityCutoff.toLowerCase()
    )
  ) {
    throw new Error(
      `Invalid severity-cutoff value is set to ${severityCutoff} - please ensure you are choosing either negligible, low, medium, high, or critical`
    )
  }
  if (
    !FORMAT_LIST.some(
      item =>
        typeof outputFormat.toLowerCase() === 'string' &&
        item === outputFormat.toLowerCase()
    )
  ) {
    throw new Error(
      `Invalid output-format value is set to ${outputFormat} - please ensure you are choosing either json or sarif`
    )
  }
  core.debug(`Installing grype version ${grypeVersion}`)
  await installGrype(grypeVersion)

  core.debug(`Source: ${source}`)
  core.debug(`Fail Build: ${failBuild}`)
  core.debug(`Severity Cutoff: ${severityCutoff}`)
  core.debug(`Only Fixed: ${onlyFixed}`)
  core.debug(`Add Missing CPEs: ${addCpesIfNone}`)
  core.debug(`Orient by CVE: ${byCve}`)
  core.debug(`Output Format: ${outputFormat}`)

  core.debug('Creating options for GRYPE analyzer')

  // Run the grype analyzer
  let cmdOutput = ''
  const cmd = `${grypeBinary}`
  if (severityCutoff !== '') {
    cmdArgs.push('--fail-on')
    cmdArgs.push(severityCutoff.toLowerCase())
  }
  if (parsedOnlyFixed === true) {
    cmdArgs.push('--only-fixed')
  }
  if (parsedAddCpesIfNone === true) {
    cmdArgs.push('--add-cpes-if-none')
  }
  if (parsedByCve === true) {
    cmdArgs.push('--by-cve')
  }
  if (vex) {
    cmdArgs.push('--vex')
    cmdArgs.push(vex)
  }
  cmdArgs.push(source)

  // This /dev/null writable stream is required so the entire Grype output
  // is not written to the GitHub action log. the listener below
  // will actually capture the output
  const outStream = new stream.Writable({
    write(buffer, encoding, next) {
      next()
    }
  })

  const exitCode = await core.group(`${cmd} output...`, async () => {
    core.info(`Executing: ${cmd} ${cmdArgs.join(' ')}`)

    return exec.exec(cmd, cmdArgs, {
      env,
      ignoreReturnCode: true,
      outStream,
      listeners: {
        stdout(buffer) {
          cmdOutput += buffer.toString()
        },
        stderr(buffer) {
          core.info(buffer.toString())
        },
        debug(message) {
          core.debug(message)
        }
      }
    })
  })

  if (core.isDebug()) {
    core.debug('Grype output:')
    core.debug(cmdOutput)
  }

  switch (outputFormat) {
    case 'sarif': {
      // const SARIF_FILE = "./results.sarif";
      // fs.writeFileSync(SARIF_FILE, cmdOutput);
      out.sarif = cmdOutput
      break
    }
    case 'json': {
      // const REPORT_FILE = "./results.json";
      // fs.writeFileSync(REPORT_FILE, );
      try {
        out.json = JSON.parse(cmdOutput).matches
      } catch {
        out.json = []
      }
      break
    }
    default: // e.g. table
      core.info(cmdOutput)
  }

  // If there is a non-zero exit status code there are a couple of potential reporting paths
  if (exitCode > 0) {
    if (!severityCutoff) {
      // There was a non-zero exit status but it wasn't because of failing severity, this must be
      // a grype problem
      core.warning('grype had a non-zero exit status when running')
    }
    // There is a non-zero exit status code with severity cut off, although there is still a chance this is grype
    // that is broken, it will most probably be a failed severity. Using warning here will make it bubble up in the
    // Actions UI
    else
      core.warning(
        `Failed minimum severity level. Found vulnerabilities with level '${severityCutoff}' or higher`
      )
  }

  return out
}

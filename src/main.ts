import * as core from '@actions/core'
import { getResultsDiff, runScan, sourceInput, mapToReport } from './utils'
import tablemark from 'tablemark'

/**
 * The main function for the action.
 */
export async function run(): Promise<void> {
  try {
    core.debug(new Date().toTimeString())
    // Grype accepts several input options, initially this action is supporting both `image` and `path`, so
    // a check must happen to ensure one is selected at least, and then return it
    const sourceArray = sourceInput()

    const failBuild = core.getInput('fail-build') || 'true'
    const outputFormat = core.getInput('output-format') || 'json'
    const severityCutoff = core.getInput('severity-cutoff') || 'medium'
    const onlyFixed = core.getInput('only-fixed') || 'false'
    const addCpesIfNone = core.getInput('add-cpes-if-none') || 'false'
    const byCve = core.getInput('by-cve') || 'true'
    const vex = core.getInput('vex') || ''

    const out = await runScan({
      source: sourceArray.head,
      failBuild: 'false',
      severityCutoff,
      onlyFixed,
      outputFormat,
      addCpesIfNone,
      byCve,
      vex
    })
    if (sourceArray.base) {
      const outbase = await runScan({
        source: sourceArray.base,
        failBuild: 'false',
        severityCutoff,
        onlyFixed,
        outputFormat,
        addCpesIfNone,
        byCve,
        vex
      })

      // core.setOutput("json", out.json);
      if (out.json && outbase.json) {
        const results = getResultsDiff(out.json, outbase.json)
        core.notice(`${results.length} Vulnerabilities found`)
        if (results.length > 0) {
          const report = mapToReport(results)
          core.setOutput('json', report)
          core.setOutput('markdown', tablemark(report))
        } else {
          core.setOutput('json', [])
          core.setOutput('markdown', '')
        }
        if (failBuild === 'true' && results.length > 0) {
          core.setFailed(`${results.length} Vulnerabilities found`)
        } else {
          if (results.length === 0) {
            core.notice(`No Vulnerabilities found`)
          } else {
            core.warning(`${results.length} Vulnerabilities found`)
          }
        }
      }
    } else {
      const results = out.json

      if (results) {
        core.info(`${results?.length} Vulnerabilities found`)
        core.setOutput('json', results)
        core.setOutput('markdown', tablemark(mapToReport(results)))
      }
      if (failBuild === 'true' && results && results?.length > 0) {
        core.setFailed(`${results.length} Vulnerabilities found`)
      }
    }
  } catch (error) {
    core.setFailed(`Action failed ${error}`)
  }
}

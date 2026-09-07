#!/usr/bin/env node
/**
 * The `prm` command-line tool.
 *
 * It contains NO verification logic of its own — everything comes from @prm/verify, so the CLI and
 * the web application can never disagree about whether a document is valid. Duplicating verification
 * in a second place is how two implementations quietly diverge.
 *
 * This tool never makes a network request, in any mode. `--offline` is accepted for clarity and to
 * make the guarantee explicit in scripts, but it changes nothing: offline is the only mode there is.
 */
import { pathToFileURL } from 'node:url'
import { cmdVerify, cmdDigest, cmdInspect, cmdVerifyChain, UsageError, type CommandResult } from './commands.js'
import { bold, dim } from './render.js'

const USAGE = `${bold('prm')} — verify PRM artifacts independently, without contacting PRM.

${bold('USAGE')}
  prm verify <file> [--kel <file>] [--chain <file>] [--offline] [--json]
  prm verify-chain <file>
  prm inspect <file>
  prm digest <file> [--kind <type>] [--bytes]
  prm --version | --help

${bold('COMMANDS')}
  verify        Verify a policy, key event log, or .prmproof bundle. The artifact type is
                detected from its contents.
  verify-chain  Verify an array of policy versions links correctly, oldest to newest.
  inspect       Show, in plain language, what a policy permits and objects to.
  digest        Print the canonical digest and which members were excluded from it.

${bold('OPTIONS')}
  --kel <file>    Key event log (one event or an array). Without it, issuer authority
                  cannot be established and is reported as unconfirmed rather than valid.
  --log-key <mb>  Transparency log public key, to check a signed tree head in a bundle.
  --chain <file>  Array of policy versions, to additionally verify the version chain.
  --offline       No-op. This tool is always offline; the flag documents that intent.
  --kind <type>   policy | authorization | keyEvent | ledgerEntry | signedTreeHead
  --bytes         Also print the exact canonical bytes the digest was computed over.
  --json          Machine-readable output.
  --no-color      Disable colour (or set NO_COLOR).

${bold('EXIT CODES')}
  0  verified          2  failed
  1  verified with warnings   3  bad usage or malformed input

${bold('EXAMPLES')}
  prm verify policy.json --kel kel.json --offline
  prm verify notice.prmproof
  prm inspect policy.json
  prm digest policy.json --bytes

${dim('Verification never requires the PRM service. If rightsroot.com is gone, this still works.')}
`

interface Parsed {
  command?: string
  positional: string[]
  flags: Record<string, string | boolean>
}

function parseArgs (argv: string[]): Parsed {
  const out: Parsed = { positional: [], flags: {} }
  const takesValue = new Set(['kel', 'chain', 'kind', 'log-key'])

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i] as string
    if (a.startsWith('--')) {
      const [name, inline] = a.slice(2).split('=', 2) as [string, string | undefined]
      if (takesValue.has(name)) {
        const value = inline ?? argv[++i]
        if (value === undefined) throw new UsageError(`--${name} requires a value`)
        out.flags[name] = value
      } else {
        out.flags[name] = inline ?? true
      }
    } else if (out.command === undefined) {
      out.command = a
    } else {
      out.positional.push(a)
    }
  }
  return out
}

function run (argv: string[]): CommandResult {
  const { command, positional, flags } = parseArgs(argv)

  if (flags.help === true || command === 'help' || command === undefined) {
    return { output: USAGE, exitCode: command === undefined && flags.help !== true ? 3 : 0 }
  }
  if (flags.version === true || command === 'version') {
    return { output: '0.1.0', exitCode: 0 }
  }

  const file = positional[0]
  const need = (): string => {
    if (file === undefined) throw new UsageError(`${command} requires a file argument`)
    return file
  }

  switch (command) {
    case 'verify':
      return cmdVerify(need(), {
        ...(typeof flags.kel === 'string' ? { kel: flags.kel } : {}),
        ...(typeof flags.chain === 'string' ? { chain: flags.chain } : {}),
        ...(typeof flags['log-key'] === 'string' ? { logKey: flags['log-key'] } : {}),
        offline: flags.offline === true,
        json: flags.json === true
      })
    case 'verify-chain':
      return cmdVerifyChain(need())
    case 'inspect':
      return cmdInspect(need())
    case 'digest':
      return cmdDigest(need(), {
        ...(typeof flags.kind === 'string' ? { kind: flags.kind } : {}),
        bytes: flags.bytes === true
      })
    default:
      throw new UsageError(`unknown command: ${command}`)
  }
}

export function main (argv: string[]): number {
  try {
    const { output, exitCode } = run(argv)
    process.stdout.write(output + '\n')
    return exitCode
  } catch (e) {
    if (e instanceof UsageError) {
      process.stderr.write(`prm: ${e.message}\n\nRun 'prm --help' for usage.\n`)
      return 3
    }
    process.stderr.write(`prm: unexpected error: ${(e as Error).message}\n`)
    return 3
  }
}

// Only auto-run when invoked as a program, so the module stays importable by tests.
const entry = process.argv[1]
if (entry !== undefined && import.meta.url === pathToFileURL(entry).href) {
  process.exitCode = main(process.argv.slice(2))
}

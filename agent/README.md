# Sentinel-AV Agent

The Sentinel-AV Agent is a malware scanning component that integrates with VirusTotal's API to detect malicious files.

## Features

- File scanning using VirusTotal's API
- Hash lookup for known malware
- Rate limiting to respect API limits (4 lookups/min, 500/day)
- Integration with the Sentinel-AV server

## Setup

1. Get a VirusTotal API key from [VirusTotal](https://www.virustotal.com/gui/join-us)

2. Create a `.env` file in the agent directory with your API key:

```bash
echo "VT_KEY=your_virustotal_api_key_here" > .env
```

The agent will automatically load environment variables from the `.env` file.
If no `.env` file is found, it will use system environment variables.

## Usage

### Running the Agent

To scan a directory:

```bash
cd cmd/agent
go run main.go -path /path/to/directory
```

### Running Tests

To test with a known malware hash:

```bash
go run test_vt_adapter.go
```

This will test the adapter using the following known malware hash:
`7389e3aada70d58854e161c98ce8419e7ab8cd93ecd11c2b0ca75c3cafed78cb`

## API Limits

The adapter implements rate limiting to respect VirusTotal's API limits:
- 4 lookups per minute
- 500 requests per day
- 15.5k requests per month

## Configuration

The agent can be configured with the following command-line flag:
- `-path`: Directory or file to scan (default: ".")
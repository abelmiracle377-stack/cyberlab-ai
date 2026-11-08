# Security Policy

## Supported scope

CyberLab AI is an early-stage security research project. Only use assessment capabilities against systems and data you own or are explicitly authorised to assess.

## Reporting a vulnerability

Do not publish exploitable details in a public issue. Contact the repository maintainer privately through GitHub's security reporting feature where available. Include:
- A concise description and affected component
- Reproduction steps using a local or authorised test environment
- Potential impact and suggested mitigation
- Relevant logs or proof-of-concept files with secrets removed

## Secrets and credentials

- Never commit API keys, access tokens, passwords, session cookies or private customer data.
- Use Vercel Sensitive Environment Variables or a local ignored .env.local file.
- Rotate any credential that may have been exposed.
- Do not paste production credentials into issues, pull requests or chat messages.

## Safe-use boundaries

The project is designed for defensive research, authorised testing, passive public-source intelligence and analysis. It does not support covert camera capture, deceptive tracking, private subscriber identity lookups, private browsing-history collection or unauthorised access.

## Disclosure

Coordinate disclosure with the maintainer before publishing details that could put users or systems at risk.

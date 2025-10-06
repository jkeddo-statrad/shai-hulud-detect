# ############################################
This is a Windows, Powershell 7 focused, fork of the Shai-Hulud detector script published here:
https://github.com/Cobenian/shai-hulud-detect


My attempt at running the original script inside
git bash for Windows took 3 days on a partial subset of my local repositories only to hang without finishing.

I wanted to antivirus at first but then I realized
git bash for Windows is not a true native core-OS-optimized tool like bash on linux/OSX is. Powershell fills that role for Windows machines, not Bash.

I spent my some time trying to vibe code a translation
of this that would run better on my work Windows machine. Changes include:

- Conversion of powershell 7 (not built in powershell version)
- Parallelization support
- More error handling (to prevent crashing)
- Resumability from error state

So far, in my testing, the conversion works. Not only that, but the script finished scanning **all** of my repositories in about 4 hours. This version of the script runs about 30-40 times faster than the original version for my Windows machine.

Please note: While I have spent time manually verifying the correctness of this script's results, I cannot verify it returns findings 100% identically to the previous script. Treat this script to be 'as-is'.

### Installing Powershell 7 (speedier)(required)

1. Install with WinGet: `winget install --id Microsoft.Powershell --source winget`
2. Open "PowerShell 7" from Start Menu or press win+R and type "pwsh", press enter.
3. You should see a shell opened saying indicating you are using Powershell 7.


### Running the Script

1. Set Powershell 7 to this directory
2. Copy paste this script and update it to use the local dirs on your PC: ` pwsh -NoLogo -NoProfile -File .\shai-hulud-detector.ps1 -ScanDir 'C:\Users\[YOUR_USERNAME]\source\organizations\statpacs\StatView2' -Parallelism 16 -StatePath 'C:\temp\shai_state.json' -ProgressLog 'C:\temp\shai_progress.log'`
3. If possible, close other heavy apps. Our company laptops have 22 logical cores, and I allocated 16 of them to running this script in step 2. Alternatively, you could also leave this script running overnight.

# ############################################
# ############################################
# ############################################
# ############################################
ORIGINAL README
# ############################################
# ############################################
# ############################################
# ############################################

# Shai-Hulud NPM Supply Chain Attack Detector

[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Shell](https://img.shields.io/badge/shell-Bash-blue)](#requirements)
[![Status](https://img.shields.io/badge/status-Active-success)](../../)
[![Contributions](https://img.shields.io/badge/contributions-Welcome-orange)](CONTRIBUTING.md)
[![Last Commit](https://img.shields.io/github/last-commit/Cobenian/shai-hulud-detect)](https://github.com/Cobenian/shai-hulud-detect/commits/main)
[![Security Tool](https://img.shields.io/badge/type-Security%20Tool-red)](#overview)


<img src="shai_hulu_detector.jpg" alt="sshd" width="80%" />

A Bash tool that helps you spot known traces of the September 2025 npm supply-chain attacks—including the Shai-Hulud self-replicating worm and the chalk/debug crypto-theft incident. It cross-checks 571+ confirmed bad package versions across multiple campaigns and checks for the most relevant red flags in your project.

## Overview

Covers multiple npm supply chain attacks from September 2025:

### **Chalk/Debug Crypto Theft Attack** (September 8, 2025)
- **Scope**: 18+ packages with 2+ billion weekly downloads
- **Attack**: Cryptocurrency wallet address replacement in browsers
- **Duration**: ~2 hours before detection
- **Packages**: chalk, debug, ansi-styles, color-*, supports-*, and others
- **Method**: XMLHttpRequest hijacking to steal crypto transactions

### **Shai-Hulud Self-Replicating Worm** (September 14-16, 2025)
- **Scope**: 517+ packages across multiple namespaces
- **Attack**: Credential harvesting and self-propagation
- **Method**: Uses Trufflehog to scan for secrets, publishes stolen data to GitHub
- **Propagation**: Self-replicates using stolen npm tokens
- **Packages**: @ctrl/*, @crowdstrike/*, @operato/*, and many others

## Quick Start

```bash
# Clone the repository
git clone https://github.com/username/shai-hulud-detector.git
cd shai-hulud-detector

# Make the script executable
chmod +x shai-hulud-detector.sh

# Scan your project for Shai-Hulud indicators
./shai-hulud-detector.sh /path/to/your/project

# For comprehensive security scanning
./shai-hulud-detector.sh --paranoid /path/to/your/project
```

## What it Detects

### High Risk Indicators
- **Malicious workflow files**: `shai-hulud-workflow.yml` files in `.github/workflows/`
- **Known malicious file hashes**: Files matching any of 7 SHA-256 hashes from different Shai-Hulud worm variants (V1-V7), sourced from [Socket.dev's comprehensive attack analysis](https://socket.dev/blog/ongoing-supply-chain-attack-targets-crowdstrike-npm-packages)
- **Compromised package versions**: Specific versions of 571+ packages from multiple attacks
- **Suspicious postinstall hooks**: Package.json files with postinstall scripts containing curl, wget, or eval commands
- **Trufflehog activity**: Files containing trufflehog references or credential scanning patterns
- **Shai-Hulud repositories**: Git repositories named "Shai-Hulud" (used for data exfiltration)

### Medium Risk Indicators
- **Suspicious content patterns**: References to `webhook.site` and the malicious endpoint `bb8ca5f6-4175-45d2-b042-fc9ebb8170b7`
- **Suspicious git branches**: Branches named "shai-hulud"
- **Semver pattern matching**: Packages that could become compromised during `npm update` due to caret (^) or tilde (~) version patterns

### Low Risk Indicators
- **Namespace warnings**: Packages from namespaces known to be affected (@ctrl, @crowdstrike, @art-ws, @ngx, @nativescript-community) but at safe versions

### Package Detection Method

The script loads a list of the compromised packages from an external file (`compromised-packages.txt`) which contains:
- **600+ confirmed compromised package versions** with exact version numbers
- **11 affected namespaces** for broader detection of packages from compromised maintainer accounts

### Maintaining and Updating the Package List

**Important**: The Shai-Hulud attack was self-replicating, meaning new compromised packages may still be discovered. The compromised packages list is stored in `compromised-packages.txt` for easy maintenance:

- **Format**: `package_name:version` (one per line)
- **Comments**: Lines starting with `#` are ignored
- **Updates**: The file can be updated as new compromised packages are discovered
- **Fallback**: If the file is missing, the script uses a core embedded list

### Staying Updated on New Compromised Packages

Check these security advisories regularly for newly discovered compromised packages:

- **[StepSecurity Blog](https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised)** - Original comprehensive analysis
- **[Semgrep Security Advisory](https://semgrep.dev/blog/2025/security-advisory-npm-packages-using-secret-scanning-tools-to-steal-credentials/)** - Detailed technical analysis
- **[JFrog Security Research](https://jfrog.com/blog/shai-hulud-npm-supply-chain-attack-new-compromised-packages-detected/)** - Ongoing detection of new packages
- **[Wiz Security Blog](https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack)** - Attack analysis with package appendix
- **[Socket.dev Blog](https://socket.dev/blog/ongoing-supply-chain-attack-targets-crowdstrike-npm-packages)** - CrowdStrike package analysis

### How to Add Newly Discovered Packages

1. Check the security advisories above for new compromised packages
2. Add them to `compromised-packages.txt` in the format `package_name:version`
3. Test the script to ensure detection works
4. Consider contributing updates back to this repository

**Coverage Note**: Multiple September 2025 attacks affected 571+ packages total. Our detection aims to provide **comprehensive coverage** across both the Shai-Hulud worm (517+ packages) and Chalk/Debug crypto theft (26+ packages) attacks. Combined with namespace-based detection, this should provide excellent protection against these sophisticated supply chain compromises.

### Core vs Paranoid Mode

**Core Mode (Default)**
- Focuses specifically on Shai-Hulud attack indicators
- Recommended for most users checking for this specific threat
- Clean, focused output with minimal false positives

**Paranoid Mode (`--paranoid`)**
- Includes all core Shai-Hulud detection PLUS additional security checks
- Adds typosquatting detection and network exfiltration pattern analysis
- **Important**: Paranoid features are general security tools, not specific to Shai-Hulud
- May produce more false positives from legitimate code
- Useful for comprehensive security auditing

## Requirements

- macOS or Unix-like system
- Bash shell
- Standard Unix tools: `find`, `grep`, `shasum`

## Output Interpretation

### Clean System
```
✅ No indicators of Shai-Hulud compromise detected.
Your system appears clean from this specific attack.
```

### Compromised System
The script will show:
- **🚨 HIGH RISK**: Definitive indicators of compromise
- **⚠️ MEDIUM RISK**: Suspicious patterns requiring manual review
- **Summary**: Count of issues found

### What to Do if Issues are Found

#### High Risk Issues
- **Immediate action required**
- Update or remove compromised packages
- Review and remove malicious workflow files
- Scan for credential theft
- Consider full system audit

#### Medium Risk Issues
- **Manual investigation needed**
- Review flagged files for legitimacy
- Check if webhook.site usage is intentional
- Verify git branch purposes

## Testing

The repository includes test cases to validate the script:

```bash
# Test on clean project (should show no issues)
./shai-hulud-detector.sh test-cases/clean-project

# Test on infected project (should show multiple issues)
./shai-hulud-detector.sh test-cases/infected-project

# Test on mixed project (should show medium risk issues)
./shai-hulud-detector.sh test-cases/mixed-project

# Test namespace warnings (should show LOW risk namespace warnings only)
./shai-hulud-detector.sh test-cases/namespace-warning

# Test semver matching (should show MEDIUM risk for packages that could match compromised versions)
./shai-hulud-detector.sh test-cases/semver-matching

# Test legitimate crypto libraries (should show MEDIUM risk only)
./shai-hulud-detector.sh test-cases/legitimate-crypto

# Test chalk/debug attack patterns (should show HIGH risk compromised packages + MEDIUM risk crypto patterns)
./shai-hulud-detector.sh test-cases/chalk-debug-attack

# Test common crypto libraries (should not trigger HIGH risk false positives)
./shai-hulud-detector.sh test-cases/common-crypto-libs

# Test legitimate XMLHttpRequest modifications (should show LOW risk only)
./shai-hulud-detector.sh test-cases/xmlhttp-legitimate

# Test malicious XMLHttpRequest with crypto patterns (should show HIGH risk crypto theft + MEDIUM risk XMLHttpRequest patterns)
./shai-hulud-detector.sh test-cases/xmlhttp-malicious

# Test lockfile false positive (should show no issues despite other package having compromised version)
./shai-hulud-detector.sh test-cases/lockfile-false-positive

# Test actual compromised package in lockfile (should show HIGH risk)
./shai-hulud-detector.sh test-cases/lockfile-compromised

# Test packages with safe lockfile versions (should show LOW risk with lockfile protection message)
./shai-hulud-detector.sh test-cases/lockfile-safe-versions

# Test mixed lockfile scenario (should show HIGH risk for compromised + LOW risk for safe)
./shai-hulud-detector.sh test-cases/lockfile-comprehensive-test

# Test packages without lockfile (should show MEDIUM risk for potential update risks)
./shai-hulud-detector.sh test-cases/no-lockfile-test

# Test typosquatting detection with paranoid mode (should show MEDIUM risk typosquatting warnings)
./shai-hulud-detector.sh --paranoid test-cases/typosquatting-project

# Test network exfiltration detection with paranoid mode (should show HIGH risk credential harvesting + MEDIUM risk network patterns)
./shai-hulud-detector.sh --paranoid test-cases/network-exfiltration-project

# Test clean project with paranoid mode (should show no issues - verifies no false positives)
./shai-hulud-detector.sh --paranoid test-cases/clean-project
```

### Paranoid Mode Testing

The `--paranoid` flag enables additional security checks beyond Shai-Hulud-specific detection:

- **Typosquatting Detection**: Identifies packages with names similar to popular packages (e.g., "raect" instead of "react", "lodsh" instead of "lodash")
- **Network Exfiltration Patterns**: Detects suspicious domains (webhook.site, pastebin.com), hardcoded IP addresses, WebSocket connections to external endpoints
- **Enhanced Security Auditing**: Useful for comprehensive project security reviews

**Note**: Paranoid mode may produce more false positives from legitimate code patterns, so review findings carefully.

### Lockfile-Aware Detection (v2.6.0+)

The script now intelligently handles projects with lockfiles to reduce false positives:

- **Lockfile Detection**: Automatically detects package-lock.json, yarn.lock, and pnpm-lock.yaml files
- **Actual Version Checking**: When semver ranges could match compromised versions, checks the actual installed version from lockfiles
- **Smart Risk Assessment**:
  - **HIGH RISK**: Lockfile contains exact compromised version (immediate threat)
  - **LOW RISK**: Lockfile contains safe version (protected by lockfile, but avoid updates)
  - **MEDIUM RISK**: No lockfile present (potential update risk)

**Example**: If your package.json has `debug@^4.0.1` (which could match compromised `debug@4.4.2`), but your lockfile pins to `debug@4.0.1`, you'll see a LOW RISK message explaining that your current installation is safe.

This feature addresses Issue #42 and eliminates confusion for users with older projects that have established lockfiles.

## How it Works

The script performs these comprehensive checks:

1. **Package Database Loading**: Loads the complete list of 571+ compromised packages from `compromised-packages.txt`
2. **Workflow Detection**: Searches for `shai-hulud-workflow.yml` files in `.github/workflows/`
3. **Hash Verification**: Calculates SHA-256 hashes of JavaScript/JSON files against 7 known malicious bundle.js variants representing the complete evolution of the Shai-Hulud worm (V1-V7)
4. **Package Analysis**: Parses `package.json` files for specific compromised versions and affected namespaces
5. **Postinstall Hook Detection**: Identifies suspicious postinstall scripts that could be used for malware propagation
6. **Content Scanning**: Greps for suspicious URLs, webhook endpoints, and malicious patterns
7. **Cryptocurrency Theft Detection**: Identifies wallet address replacement patterns, XMLHttpRequest hijacking, and known crypto theft functions from the September 8 attack
8. **Trufflehog Activity Detection**: Looks for evidence of credential scanning tools and secret harvesting
9. **Git Analysis**: Checks for suspicious branch names and repository names
10. **Repository Detection**: Identifies "Shai-Hulud" repositories used for data exfiltration
11. **Package Integrity Checking**: Analyzes package-lock.json and yarn.lock files for compromised packages and suspicious modifications

## Limitations

- **Hash Detection**: Only detects files with exact matches to the 7 known malicious bundle.js hashes
- **Package Versions**: Detects specific compromised versions and namespace warnings, but new compromised versions may not be detected
- **False Positives**: Legitimate use of webhook.site, Trufflehog for security, or postinstall hooks will trigger alerts
- **Worm Evolution**: The self-replicating nature means new variants may emerge with different signatures
- **Coverage**: Covers known compromised packages from major September 2025 attacks
- **Package Integrity**: Relies on lockfile analysis to detect compromised packages, but sophisticated attacks may evade detection

## Contributing

If you discover additional IoCs or compromised packages related to the Shai-Hulud attack, please update the arrays in the script and test thoroughly.

## Security Note

This script is for **detection only**. It does not:
- Automatically remove malicious code
- Fix compromised packages
- Prevent future attacks

Always verify findings manually and take appropriate remediation steps.

## Latest Threat Intelligence Updates

### s1ngularity/Nx Connection (September 2025)
Recent investigations have revealed a potential connection between the Shai-Hulud campaign and the Nx package ecosystem:
- **Repository Migration Patterns**: Attackers are using repositories with "-migration" suffixes to distribute malicious packages
- **Advanced Package Integrity Checks**: Double base64-encoded `data.json` files have been discovered in compromised package versions
- **Additional Compromised Versions**: `tinycolor@4.1.1` and `tinycolor@4.1.2` have been identified as compromised
- **New Package Targets**: `angulartics2` and `koa2-swagger-ui` packages have been added to the compromised list

### Enhanced Detection Capabilities (v2.5.0)
The script now includes:
- **Fixed lockfile false positives**: Improved package version extraction to prevent incorrect flagging of safe packages (fixes issue #37)
- **Robust lockfile parsing**: Uses block-based JSON parsing instead of proximity-based grep to accurately extract package versions
- **Context-aware XMLHttpRequest detection**: Reduces false positives for legitimate framework code (React Native, Next.js)
- **Improved risk stratification**: XMLHttpRequest modifications now properly classified based on context and crypto patterns
- **Parallel processing optimization**: ~20% performance improvement with semver pattern matching
- **Duplicate-free package database**: Cleaned 600+ unique compromised package entries
- Repository migration pattern detection
- Package-lock.json integrity verification
- Context-aware Trufflehog detection to reduce false positives
- Risk level classification (HIGH/MEDIUM/LOW) for better triage

## References

### Primary Sources
- [StepSecurity Blog: CTRL, tinycolor and 40 NPM packages compromised](https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised)
- [JFrog: New compromised packages in largest npm attack in history](https://jfrog.com/blog/new-compromised-packages-in-largest-npm-attack-in-history/)
- [Aikido: NPM debug and chalk packages compromised](https://www.aikido.dev/blog/npm-debug-and-chalk-packages-compromised)
- [Semgrep Security Advisory: NPM packages using secret scanning tools to steal credentials](https://semgrep.dev/blog/2025/security-advisory-npm-packages-using-secret-scanning-tools-to-steal-credentials/)
- [Aikido: S1ngularity-nx attackers strike again](https://www.aikido.dev/blog/s1ngularity-nx-attackers-strike-again)

### Additional Resources
- [Socket: Ongoing supply chain attack targets CrowdStrike npm packages](https://socket.dev/blog/ongoing-supply-chain-attack-targets-crowdstrike-npm-packages)
- [Ox Security: NPM 2.0 hack: 40+ npm packages hit in major supply chain attack](https://www.ox.security/blog/npm-2-0-hack-40-npm-packages-hit-in-major-supply-chain-attack/)
- [Phoenix Security: NPM tinycolor compromise](https://phoenix.security/npm-tinycolor-compromise/)

### Attack Details
- **Initial Discovery**: September 15, 2025
- **Scale**: 571+ packages compromised across multiple attack campaigns
- **Attack Type**: Self-replicating worm using postinstall hooks
- **Malicious Endpoint**: `https://webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7`
- **Exfiltration Method**: GitHub repositories named "Shai-Hulud"

## Contributing

We welcome contributions to improve any of the code, documentation, tests and packages covered. 

### How to Contribute

#### Adding New Compromised Packages

1. **Fork the repository**
   ```bash
   git clone https://github.com/yourusername/shai-hulud-detector.git
   cd shai-hulud-detector
   ```

2. **Update the package list**
   - Add new packages to `compromised-packages.txt` in the format `package_name:version`
   - Include a source/reference for where you found the compromised package
   - Group packages by namespace for organization

3. **Test your changes**
   ```bash
   # Test that the script loads the new packages
   ./shai-hulud-detector.sh test-cases/clean-project

   # Run all test cases to ensure nothing breaks
   ./shai-hulud-detector.sh test-cases/infected-project
   ./shai-hulud-detector.sh test-cases/mixed-project
   ```

4. **Submit a Pull Request**
   - Create a descriptive PR title (e.g., "Add @example/package compromised versions")
   - Include details about the source of the information
   - Reference any security advisories or reports
   - Explain any version patterns or attack details

#### Other Contributions

- **Bug fixes**: Report and fix issues with detection accuracy
- **New IoCs**: Add detection for additional indicators of compromise
- **Documentation**: Improve clarity and add examples
- **Test cases**: Add new test scenarios for edge cases

### Contribution Guidelines

- **Verify sources**: Only add packages confirmed by reputable security firms
- **Test thoroughly**: Ensure changes don't break existing functionality
- **Document changes**: Update relevant documentation and changelog
- **Follow patterns**: Match existing code style and organization
- **Security first**: Never include actual malicious code in test cases

### Reporting New Compromised Packages

If you can't submit a PR, you can still help by reporting new compromised packages:

1. Open an issue with the title "New compromised package: [package-name]"
2. Include the package name, version, and source of information
3. Provide links to security advisories or reports
4. We'll review and add verified packages to the detection list

## Release Notes

For a complete list of changes and version history, see the [CHANGELOG.md](CHANGELOG.md).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

# vbs-rs

This code repository is dedicated to testing Windows Virtualization-Based Security (VBS) features for learning purposes, do not use it for production.

## Focus

The primary focus is on:

- VBS enclave operations such as creating and terminating enclaves, data sealing, and attestation, etc. For more information, refer to [Virtualization-based security (VBS) enclaves](https://learn.microsoft.com/en-us/windows/win32/trusted-execution/vbs-enclaves).
- Exploring advanced key protection based on VBS.

According to [Microsoft's official blog post](https://techcommunity.microsoft.com/t5/windows-it-pro-blog/advancing-key-protection-in-windows-using-vbs/ba-p/4050988), keys protected using VBS cannot be dumped from process memory or exported in plain text from a user’s machine. This effectively prevents exfiltration attacks by any admin-level attacker.

## Goal

The `vbs-rs` project aims to provide a Rust-based solution for interacting with these VBS features, offering a more secure and reliable approach to key protection and management in Windows environments.


## License

This project is licensed under the MIT License.
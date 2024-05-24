use std::mem;
use windows::{
    core::*, Win32::Foundation::*, Win32::Security::Cryptography::*, Win32::System::Environment::*,
    Win32::System::SystemServices::*, Win32::System::Threading::*,
};

fn main() -> Result<()> {
    // test vbs enclave operations
    vbsenclave();

    // test vbs key protections
    vbskey();

    Ok(())
}

#[repr(C, packed(1))]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[derive(Clone, Copy)]
pub struct ENCLAVE_CREATE_INFO_VBS {
    pub Flags: u32,
    pub OwnerID: [i8; 32],
}

fn vbsenclave() {
    unsafe {
        // check if vbs enclave  is supported
        let issupported = IsEnclaveTypeSupported(ENCLAVE_TYPE_VBS);
        if let Err(_err) = issupported {
            println!("VBS Enclave is not supported");
            return;
        }

        // Get the current process's handle
        let h_process = GetCurrentProcess();

        // fill up the enclave creation parameters
        let vbsinfo = ENCLAVE_CREATE_INFO_VBS {
            Flags: 0,
            OwnerID: [0; 32],
        };

        let infosize = mem::size_of::<ENCLAVE_CREATE_INFO_VBS>() as u32;

        // Create the enclave with ?MB of dwsize
        println!("Creating enclave");
        let henclave = CreateEnclave(
            h_process,
            None,
            1024 * 1024 * 2 * 10, // must be a multiple of 2 MB in size (Bytes)
            0,                    // not used for VBS enclave
            ENCLAVE_TYPE_VBS,
            &vbsinfo as *const _ as *const _,
            infosize,
            None,
        );

        if henclave.is_null() {
            println!("Failed to create enclave");
        } else {
            println!("Enclave created successfully");

            // TODO:
            // load enclave code/data, init and more ...

            // delete the enclave
            let status = DeleteEnclave(henclave);
            if status.is_err() {
                println!("Failed to delete enclave");
            } else {
                println!("Enclave deleted successfully");
            }
        }
    }
}

pub const NCRYPT_REQUIRE_VBS_FLAG: NCRYPT_FLAGS = NCRYPT_FLAGS(131072u32);
pub const AT_NOT_SIGNATURE_NOT_KEYEXCHANGE: CERT_KEY_SPEC = CERT_KEY_SPEC(0u32);

// Example:
// Creating a key with virtualization-based security
// The following sample code shows how to create a 2048-bit VBS key with the RSA algorithm:
// reference:
// https://techcommunity.microsoft.com/t5/windows-it-pro-blog/advancing-key-protection-in-windows-using-vbs/ba-p/4050988
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
fn vbskey() {
    vbsenumeration();

    let mut hProv = Default::default();
    let mut hRsaKey: NCRYPT_KEY_HANDLE = Default::default();
    let mut hAESKey: NCRYPT_KEY_HANDLE = Default::default();
    let kprovider = MS_KEY_STORAGE_PROVIDER;
    // Open the key storage provider and create apersisted vbs key
    unsafe {
        // Open the key storage provider
        let status = NCryptOpenStorageProvider(&mut hProv, kprovider, 0);
        if status.is_err() {
            println!("NCryptOpenStorageProvider failed with {:?}", status);
            return;
        }

        // Create a persisted RSA key with the VBS flag
        let status = NCryptCreatePersistedKey(
            hProv,
            &mut hRsaKey,
            NCRYPT_RSA_ALGORITHM,
            w!("BingVbsRsaKeyName"),
            AT_NOT_SIGNATURE_NOT_KEYEXCHANGE,
            NCRYPT_REQUIRE_VBS_FLAG,
        );

        if status.is_err() {
            println!("NCryptCreatePersistedKey failed with {:?}", status);
            let _ = NCryptFreeObject(hProv);
            return;
        }

        println!("Created a persisted VBS Guard RSA key {:?}!", hRsaKey);

        // Set the key size to 2048 bits
        let dwKeySize: u32 = 2048;
        let status = NCryptSetProperty(
            hRsaKey,
            NCRYPT_LENGTH_PROPERTY,
            dwKeySize.to_le_bytes().as_slice(), // use little-endian byte order for x86
            NCRYPT_FLAGS(0),
        );
        if status.is_err() {
            println!("NCryptSetProperty failed with {:?}", status);
            let _ = NCryptDeleteKey(hRsaKey, NCRYPT_SILENT_FLAG.0);
            let _ = NCryptFreeObject(hProv);
            return;
        }

        // Finalize the key to make it usable
        let status = NCryptFinalizeKey(hRsaKey, NCRYPT_FLAGS(0));
        if status.is_err() {
            println!("NCryptFinal failed with {:?}", status);
            let _ = NCryptDeleteKey(hRsaKey, NCRYPT_SILENT_FLAG.0);
            let _ = NCryptFreeObject(hProv);
            return;
        }

        //TODO: now we can use this key after finalizing it, e.g. NCryptEncrypt, NCryptSignHash ...

        let iskey = NCryptIsKeyHandle(hRsaKey);
        if iskey.eq(&true) {
            println!("NCryptIsKeyHandle return with {:?}", iskey);
        }

        let status = NCryptCreatePersistedKey(
            hProv,
            &mut hAESKey,
            NCRYPT_AES_ALGORITHM,
            w!("BingVbsAesKeyName"),
            CERT_KEY_SPEC(0),
            NCRYPT_REQUIRE_VBS_FLAG,
        );
        if status.is_err() {
            println!("NCryptCreatePersistedKey failed with {:?}", status);
        } else {
            println!("Created a persisted VBS Guard AES key {:?}!", hAESKey);

            let dwKeySize: u32 = 256;
            let status = NCryptSetProperty(
                hAESKey,
                NCRYPT_LENGTH_PROPERTY,
                dwKeySize.to_le_bytes().as_slice(), // use little-endian byte order for x86
                NCRYPT_FLAGS(0),
            );
            if status.is_err() {
                println!("NCryptSetProperty failed with {:?}", status);
            } else {
                let status = NCryptFinalizeKey(hAESKey, NCRYPT_FLAGS(0));
                if status.is_err() {
                    println!("NCryptFinal failed with {:?}", status);
                } else {
                    println!("AES key finalized successfully")

                    // TODO: use this AES to do something like encrytion?
                }
            }
        }

        vbsenumeration();

        if NCryptDeleteKey(hAESKey, NCRYPT_SILENT_FLAG.0).is_ok() {
            println!("Deleted the AES key");
        }

        // When you have finished using this handle, release it by passing it to the NCryptFreeObject function.
        // To delete the key file on disk, pass the handle to the NCryptDeleteKey function.
        if NCryptDeleteKey(hRsaKey, NCRYPT_SILENT_FLAG.0).is_ok() {
            println!("Deleted the RSA key");
        }

        if NCryptFreeObject(hProv).is_ok() {
            println!("Freed the key provider");
        }
    }
}

#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
fn vbsenumeration() {
    // enumerate the names of the registered key storage providers
    // with NCryptEnumStorageProviders()
    let mut dwProviderCount: u32 = 0;
    let mut ppProviderList = std::ptr::null_mut();
    let status;

    // Enumerate the key storage providers
    unsafe {
        status = NCryptEnumStorageProviders(&mut dwProviderCount, &mut ppProviderList, 0);

        if status.is_err() {
            println!("NCryptEnumStorageProviders failed with {:?}", status);
            return;
        }
        println!(
            "Number of registered key storage providers: {}",
            dwProviderCount
        );

        let providers: &[NCryptProviderName] =
            std::slice::from_raw_parts(ppProviderList as _, dwProviderCount as usize);

        // print all the providers
        for provider in providers {
            if !provider.pszName.is_null() {
                println!("Provider: {}", provider.pszName.display());
            }
            if !provider.pszComment.is_null() {
                println!("Provider: {}", provider.pszComment.display());
            }
        }

        // either is ok for below two ways to free buffer ?
        let _ = NCryptFreeBuffer(ppProviderList as *mut std::ffi::c_void);
        // let _ = NCryptFreeBuffer(std::mem::transmute::<*mut _, *mut std::ffi::c_void>(
        //     ppProviderList,
        // ));
    }

    let mut hProv = Default::default();
    let kprovider = MS_KEY_STORAGE_PROVIDER; // or MS_PLATFORM_KEY_STORAGE_PROVIDER
    unsafe {
        let status = NCryptOpenStorageProvider(&mut hProv, kprovider, 0);
        if status.is_err() {
            println!(
                "NCryptOpenStorageProvider failed with {:?} for {}",
                status,
                kprovider.display()
            );
            return;
        }
    }

    let mut enumstate = std::ptr::null_mut();

    loop {
        let mut ppKeyName = std::ptr::null_mut();
        unsafe {
            // The NCryptEnumKeys function obtains the names of the keys that are stored by the provider.
            let status =
                NCryptEnumKeys(hProv, None, &mut ppKeyName, &mut enumstate, NCRYPT_FLAGS(0));
            if let Err(err) = status {
                if err.code().eq(&NTE_NO_MORE_ITEMS) {
                    println!("No more keys found");
                    break;
                } else {
                    println!("NCryptEnumKeys failed with {:?}", err);
                }
                break;
            } else {
                let keys: &[NCryptKeyName] = std::slice::from_raw_parts(ppKeyName as _, 1usize);
                for key in keys {
                    if !key.pszName.is_null() {
                        println!("Key Name: {}", key.pszName.display());
                    }
                    if !key.pszAlgid.is_null() {
                        println!("Key Alg: {}", key.pszAlgid.display());
                    }
                    println!("Key Spec: {:?}", key.dwLegacyKeySpec);
                    println!("Key Flags: {}", key.dwFlags);
                }
                let _ = NCryptFreeBuffer(ppKeyName as *mut std::ffi::c_void);
            }
        }
    }

    unsafe {
        let _ = NCryptFreeBuffer(enumstate);
    }

    // The NCryptEnumAlgorithms function obtains the names of the algorithms that are supported by the specified key storage provider.

    let mut ppAlgList = std::ptr::null_mut();
    let mut pdwAlgCount = 0;
    unsafe {
        let status = NCryptEnumAlgorithms(
            hProv,
            NCRYPT_OPERATION(0),
            &mut pdwAlgCount,
            &mut ppAlgList,
            0,
        );
        if status.is_err() {
            println!("NCryptEnumAlgorithms failed with {:?}", status);
            return;
        }
        println!("Number of algorithms: {}", pdwAlgCount);
        let AlgList: &[NCryptAlgorithmName] = std::slice::from_raw_parts(
            ppAlgList as *const NCryptAlgorithmName,
            pdwAlgCount as usize,
        );
        for alg in AlgList {
            if !alg.pszName.is_null() {
                println!("Algorithm Name: {}", alg.pszName.display());
            }
            println!("Algorithm Class: {:?}", alg.dwClass);
            println!("Algorithm Operations: {:?}", alg.dwAlgOperations);
            println!("Algorithm Flags: {}", alg.dwFlags);
        }
        let _ = NCryptFreeBuffer(ppAlgList as *mut std::ffi::c_void);
    }

    unsafe {
        if NCryptFreeObject(hProv).is_ok() {
            println!("Freed the key provider");
        }
    }
}

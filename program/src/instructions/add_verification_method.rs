//! Add a verification method under an authority's signature. The account
//! grows by the entry's exact size, funded by the payer.

use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};

use crate::{
    events,
    instructions::shared::*,
    reader::{Args, Reader},
    state::*,
};

pub fn process(accounts: &mut [AccountView], args: &[u8]) -> ProgramResult {
    let Update {
        payer,
        authority,
        did_account,
        controller,
        subject,
    } = Update::try_from(accounts)?;

    // The borsh args are VerificationMethod { fragment, method_type, flags, key_data }.
    let mut r = Reader::<Args>::new(args);
    let fragment = r.str()?;
    let method_type = r.u8()?;
    let flags = r.u16()?;
    let key_data = r.len_prefixed()?;
    r.finish()?;
    expected_key_len(method_type).ok_or(ProgramError::InvalidInstructionData)?;

    let signer_key = authority.address().as_array();
    let method = NewMethod {
        fragment,
        method_type,
        flags,
        key_len: key_data.len(),
    };

    let s = {
        let data = did_account.try_borrow()?;
        let doc = DidView::parse(&data)?;
        authorize(&doc, signer_key, controller)?;
        doc.check_new_method(&method)?;
        check_new_key(&method, key_data, signer_key)?;
        *doc.sections()
    };

    grow(
        did_account,
        payer,
        s.end + vm_space(fragment.len(), key_data.len()),
    )?;
    let now = Clock::get()?.unix_timestamp;

    let new_version = {
        let mut data = did_account.try_borrow_mut()?;
        insert_vm(&mut data, &s, &method, key_data);
        touch(&mut data, now);
        version(&data)
    };

    events::emit(
        &events::DID_MODIFIED,
        did_account.address(),
        &subject,
        new_version,
    );
    Ok(())
}

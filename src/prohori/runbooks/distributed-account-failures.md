# Failed sign-ins for one account from many addresses

**Rules:** PRH-AUTH-005

## What it means

One existing account failed to sign in from several different addresses within an hour. An
attacker spreading guesses over many addresses (a botnet, rotating proxies) stays under the
per-address limits; counting per account shows that one account is the target.

## Triage

1. Check whether any sign-in to the account succeeded during or after the failures (PRH-AUTH-010).
2. Compare the addresses with the account's usual ones: country, provider, VPN or hosting range.
3. Ask whether the owner changed their password recently: old devices retry the stale password.
4. Look for the same addresses failing on other accounts (PRH-AUTH-002, PRH-AUTH-008).

## Recommended actions

- Make the account owner confirm recent activity; if anything looks wrong, reset the password and
  end every session.
- Require two-step verification for the account.
- For the web app, add progressive delays or a bot check per account, not only per address.
- For SSH, disable password authentication and allow keys only.

## False positives

- A user who moves between home, mobile and office networks and mistypes the password on each.
- A password manager or mail client on several devices retrying a stale password after a change.

## ATT&CK

- T1110 Brute Force, T1110.001 Password Guessing (Credential Access)

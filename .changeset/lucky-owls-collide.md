---
'seamless-auth-api': patch
---

Adding an organization member twice at once answers `409` rather than `500`.

`addMember` checks for an existing membership and then creates one, in two statements with
no transaction between them. Two administrators acting on a newly invited person, or one
client retrying after a timeout, both pass the check and both insert. The unique index on
`organization_memberships (organization_id, user_id)` refuses the second, and with no
handler for it the error reached the generic handler as `500 { "error": "Internal server
error" }`.

That duplicate now answers the `409 { "error": "User is already an organization member" }`
the sequential case has always answered. Any other failure still reaches the generic
handler unchanged.

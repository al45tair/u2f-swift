What is this?
=============

I was toying with some code that used a U2F key directly from an application,
rather than having to work via a web browser.  The code in this repository was
rudely extracted from a project I was working on, but I think includes the
parts you need to get going.

It isn't presently in the form of a supported library, or a Cocoa pod, or a
Swift package, or anything like that; it isn't particularly extensively
commented, or documented, and I haven't had time to write a nice sample
application either.  It supports U2F, not the newer protocol, and not the
older one either.  But you can probably see how to extend it if you wish.

What's the license?
------------------

It's MIT licensed.  See LICENSE.

If you use it somewhere, it'd be nice to know that fact.

How do I use it?
----------------

You'll need to create a U2FManager object and you'll probably want to register
for the U2FDeviceListDidChange notification, to detect when the user inserts
(or removes) a U2F device.

To register a device, you call U2FManager's "register" method, passing in the
challenge dictionary, which has two keys, "challenge" and "origin"; the former
should be a Base64-encoded string containing the challenge data, and the latter
should be your facet ID (for a Mac app, typically something like
"bundle:com.foo.bar").

The register method also accepts a block that gives you the device, challenge
data (in JSON form), public key, key handle, attestation certificate and
signature.  So the register call looks something like this:

  let challenge : [String:Any] = [
      "challenge": challengeData.base64EncodedString(),
      "origin": "bundle:com.foo.bar"
      ]
  u2fManager.register(challenge: challenge) {
    (device, challengeJSON, publicKey, keyHandle, attestationCertificate,
     signature) in
    ...
  }

To authenticate using U2F, you use the "authenticate" method, which again takes
a challenge, a list of key handles your system knows about and a block that is
used to handle the response.  So it looks like:

  let challenge : [String:Any] = [
      "challenge": challengeData.base64EncodedString(),
      "origin": "bundle.com.foo.bar"
      ]
  u2fManager.authenticate(challenge: challenge,
  		          keyHandles: keyHandles) {
    (status, challenge, responses) in
    if status == .failed {
      // Tell the user somehow
      return
    }

    if responses.count == 0 {
      // No responses; maybe retry? [A]
      return
    }

    // Otherwise, responses is a list of U2FAuthResponse structs containing
    // the relevant information
  }

In practice you may want to write the callback as a separate function/method
because that makes it easy to trigger a retry from [A], above, as you can just
call u2fManager.authenticate again.


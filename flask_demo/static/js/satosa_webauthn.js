function b64enc(buf) {
    return base64js.fromByteArray(buf)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");
}

function b64RawEnc(buf) {
    return base64js.fromByteArray(buf)
        .replace(/\+/g, "-")
        .replace(/\//g, "_");
}

function hexEncode(buf) {
    return Array.from(buf)
        .map(function (x) {
            return ("0" + x.toString(16)).substr(-2);
        })
        .join("");
}

async function fetch_json(url, options) {
    const response = await fetch(url, options);
    const body = await response.json();
    if (body.fail)
        throw body.fail;
    return body;
}

async function fetch_text1(url, options, manage) {
    const response = await fetch(url, options);
    var a = response.clone()
    var returned = ""
    a.text().then((x) => {
        if (manage) {
            window.location.replace("/credentials");
        } else {
            window.location.replace("/logout");
        }
    })
    return returned
}

/**
 * Get PublicKeyCredentialRequestOptions for this user from the server
 * formData of the registration form
 * @param {FormData} formData
 */
const getCredentialRequestOptionsFromServer = async (formData) => {
    return await fetch_json(
        "/webauthn_begin_assertion",
        {
            method: "POST",
            body: formData
        }
    );
}

const transformCredentialRequestOptions = (credentialRequestOptionsFromServer) => {
    let {challenge, allowCredentials} = credentialRequestOptionsFromServer;

    challenge = Uint8Array.from(
        atob(challenge.replace(/\_/g, "/").replace(/\-/g, "+")), c => c.charCodeAt(0));

    allowCredentials = allowCredentials.map(credentialDescriptor => {
        let {id} = credentialDescriptor;
        id = id.replace(/\_/g, "/").replace(/\-/g, "+");
        id = Uint8Array.from(atob(id), c => c.charCodeAt(0));
        return Object.assign({}, credentialDescriptor, {id});
    });

    const transformedCredentialRequestOptions = Object.assign(
        {},
        credentialRequestOptionsFromServer,
        {challenge, allowCredentials});

    return transformedCredentialRequestOptions;
};
/**
 * Get PublicKeyCredentialRequestOptions for this user from the server
 * formData of the registration form
 * @param {FormData} formData
 */
const getCredentialCreateOptionsFromServer = async (formData) => {
    return await fetch_json(
        "/webauthn_begin_activate",
        {
            method: "POST",
            body: formData
        }
    );
}

/**
 * Transforms items in the credentialCreateOptions generated on the server
 * into byte arrays expected by the navigator.credentials.create() call
 * @param {Object} credentialCreateOptionsFromServer
 */
const transformCredentialCreateOptions = (credentialCreateOptionsFromServer) => {
    let {challenge, user} = credentialCreateOptionsFromServer;
    user.id = Uint8Array.from(
        atob(credentialCreateOptionsFromServer.user.id
            .replace(/\_/g, "/")
            .replace(/\-/g, "+")
        ),
        c => c.charCodeAt(0));

    challenge = Uint8Array.from(
        atob(credentialCreateOptionsFromServer.challenge
            .replace(/\_/g, "/")
            .replace(/\-/g, "+")
        ),
        c => c.charCodeAt(0));

    const transformedCredentialCreateOptions = Object.assign(
        {}, credentialCreateOptionsFromServer,
        {challenge, user});

    return transformedCredentialCreateOptions;
}


/**
 * Transforms the binary data in the credential into base64 strings
 * for posting to the server.
 * @param {PublicKeyCredential} newAssertion
 */
const transformNewAssertionForServer = (newAssertion) => {
    const attObj = new Uint8Array(
        newAssertion.response.attestationObject);
    const clientDataJSON = new Uint8Array(
        newAssertion.response.clientDataJSON);
    const rawId = new Uint8Array(
        newAssertion.rawId);

    const registrationClientExtensions = newAssertion.getClientExtensionResults();

    return {
        id: newAssertion.id,
        rawId: b64enc(rawId),
        type: newAssertion.type,
        attObj: b64enc(attObj),
        clientData: b64enc(clientDataJSON),
        registrationClientExtensions: JSON.stringify(registrationClientExtensions)
    };
}

async function webauthn_register(e) {
    e.preventDefault();

    // gather the data in the form
    const form = document.querySelector('#register-form');
    const formData = new FormData(form);

    // post the data to the server to generate the PublicKeyCredentialCreateOptions
    let credentialCreateOptionsFromServer;
    try {
        credentialCreateOptionsFromServer = await getCredentialCreateOptionsFromServer(formData);
    } catch (err) {
        return console.error("Failed to generate credential request options:", err);
    }

    // convert certain members of the PublicKeyCredentialCreateOptions into
    // byte arrays as expected by the spec.
    const publicKeyCredentialCreateOptions = transformCredentialCreateOptions(credentialCreateOptionsFromServer);

    // request the authenticator(s) to create a new credential keypair.
    let credential;
    try {
        credential = await navigator.credentials.create({
            publicKey: publicKeyCredentialCreateOptions
        });
    } catch (err) {
        return console.error("Error creating credential:", err);
    }

    // we now have a new credential! We now need to encode the byte arrays
    // in the credential into strings, for posting to our server.
    return transformNewAssertionForServer(credential);
}

async function turn_off() {
    const response = await fetch("/turn_off_auth");
    var a = response.clone()
    a.text().then((x) => {
        if (x == "off") {
            alert("The requiring of authentication has been turned off for " + timeout + " seconds.")
            location.reload();
        } else {
            alert("Error.")
        }
    })
}

async function turn_on() {
    const response = await fetch("/turn_on_auth");
    var a = response.clone()
    a.text().then((x) => {
        if (x == "on") {
            alert("The requiring of authentication is turned on now")
            location.reload();
        } else {
            alert("Error.")
        }
    })
}

async function webauthn_login(e) {
    e.preventDefault();
    // gather the data in the form
    const form = document.querySelector('#login-form');
    const formData = new FormData(form);

    // post the login data to the server to retrieve the PublicKeyCredentialRequestOptions
    let credentialCreateOptionsFromServer;
    try {
        credentialRequestOptionsFromServer = await getCredentialRequestOptionsFromServer(formData);
    } catch (err) {
        return console.error("Error when getting request options from server:", err);
    }

    // convert certain members of the PublicKeyCredentialRequestOptions into
    // byte arrays as expected by the spec.
    const transformedCredentialRequestOptions = transformCredentialRequestOptions(
        credentialRequestOptionsFromServer);

    // request the authenticator to create an assertion signature using the
    // credential private key
    let assertion;
    try {
        assertion = await navigator.credentials.get({
            publicKey: transformedCredentialRequestOptions,
        });
    } catch (err) {
        return console.error("Error when creating credential:", err);
    }

    // we now have an authentication assertion! encode the byte arrays contained
    // in the assertion data as strings for posting to the server
    return transformAssertionForServer(assertion);
}


const didClickManage = async (e) => {
    const transformedAssertionForServer = await webauthn_login(e)
    let response;
    try {
        response = await postAssertionToServer(transformedAssertionForServer, true);
    } catch (err) {
        return console.error("Error when validating assertion on server:", err);
    }
};

/**
 * Callback executed after submitting login form
 * @param {Event} e
 */
const didClickLogin = async (e) => {


    // post the assertion to the server for verification.
    const transformedAssertionForServer = await webauthn_login(e)
    let response;
    try {
        response = await postAssertionToServer(transformedAssertionForServer, false);
    } catch (err) {
        return console.error("Error when validating assertion on server:", err);
    }
};

const didClickRegister = async (e) => {
    const newAssertionForServer = await webauthn_register(e)
    let assertionValidationResponse;
    try {
        assertionValidationResponse = await postNewAssertionToServer(newAssertionForServer);
        window.location.replace("/credentials");
    } catch (err) {
        alert("Registration failed.")
        return console.error("Server validation of credential failed:", err);
    }
}

/**
 * Posts the new credential data to the server for validation and storage.
 * @param {Object} credentialDataForServer
 */
const postNewAssertionToServer = async (credentialDataForServer) => {
    const formData = new FormData();
    Object.entries(credentialDataForServer).forEach(([key, value]) => {
        formData.set(key, value);
    });

    return await fetch_json(
        "/verify_credential_info", {
            method: "POST",
            body: formData
        });
}

const didClickNewRegister = async (e) => {
    const newAssertionForServer = await webauthn_register(e)
    let assertionValidationResponse;
    try {
        assertionValidationResponse = await postTotallyNewAssertionToServer(newAssertionForServer);
    } catch (err) {
        return console.error("Server validation of credential failed:", err);
    }
}

/**
 * Encodes the binary data in the assertion into strings for posting to the server.
 * @param {PublicKeyCredential} newAssertion
 */
const transformAssertionForServer = (newAssertion) => {
    const authData = new Uint8Array(newAssertion.response.authenticatorData);
    const clientDataJSON = new Uint8Array(newAssertion.response.clientDataJSON);
    const rawId = new Uint8Array(newAssertion.rawId);
    const sig = new Uint8Array(newAssertion.response.signature);
    const assertionClientExtensions = newAssertion.getClientExtensionResults();

    return {
        id: newAssertion.id,
        rawId: b64enc(rawId),
        type: newAssertion.type,
        authData: b64RawEnc(authData),
        clientData: b64RawEnc(clientDataJSON),
        signature: hexEncode(sig),
        assertionClientExtensions: JSON.stringify(assertionClientExtensions)
    };
};

/**
 * Post the assertion to the server for validation and logging the user in.
 * @param {Object} assertionDataForServer
 */
const postAssertionToServer = async (assertionDataForServer, manage) => {
    const formData = new FormData();
    Object.entries(assertionDataForServer).forEach(([key, value]) => {
        formData.set(key, value);
    });

    var result = await fetch_text1(
        "/verify_assertion", {
            method: "POST",
            body: formData
        }, manage);
    return result
}
/**
 * Posts the new credential data to the server for validation and storage.
 * @param {Object} credentialDataForServer
 */
const postTotallyNewAssertionToServer = async (credentialDataForServer) => {
    const formData = new FormData();
    Object.entries(credentialDataForServer).forEach(([key, value]) => {
        formData.set(key, value);
    });

    return await fetch_text(
        "/verify_credential_info", {
            method: "POST",
            body: formData
        });
}

async function fetch_text(url, options) {
    const response = await fetch(url, options);
    var a = response.clone()
    var returned = ""
    a.text().then((x) => {
        window.location.replace("/logout");
    })
    return returned
}


function delete_credential(cred_id) {
    var url = "/delete/" + cred_id;
    fetch(url, {method: "GET"});
    setTimeout(function () {
        window.location.reload();
    }, 500)
}

disappeared = false

function disappear(el) {
    if (!disappeared) {
        disappeared = true
        setTimeout(function () {
            el.value = ''
        }, 100)
    }
}

document.addEventListener("DOMContentLoaded", e => {
    try {
        document.querySelector('#login').addEventListener('click', didClickLogin);
    } catch (e) {
    }
    try {
        document.querySelector('#manage').addEventListener('click', didClickManage);
    } catch (e) {
    }
    try {
        document.querySelector('#register').addEventListener('click', didClickRegister);
    } catch (e) {
    }
    try {
        document.querySelector('#new_register').addEventListener('click', didClickNewRegister);
    } catch (e) {
    }
});



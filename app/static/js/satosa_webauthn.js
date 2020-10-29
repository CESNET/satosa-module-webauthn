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
            window.location.href = document.getElementById('manage-url').href;
        } else {
            window.location.href = document.getElementById('logout-url').href;
        }
    })
    return returned
}

/**
 * Submit a form
 * @param {string} url
 * @param {string} method
 * @param {FormData} formData
 */
async function submitForm(url, method, formData) {
    return await fetch_json(
        url,
        {
            method: method.toUpperCase(),
            body: formData
        }
    );
}

function transformCredentialRequestOptions(credentialRequestOptionsFromServer) {
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
}

/**
 * Transforms items in the credentialCreateOptions generated on the server
 * into byte arrays expected by the navigator.credentials.create() call
 * @param {Object} credentialCreateOptionsFromServer
 */
function transformCredentialCreateOptions(credentialCreateOptionsFromServer) {
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
function transformNewAssertionForServer(newAssertion) {
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

async function webauthn_register(form) {
    // gather the data in the form
    const url = form.action;
    const method = form.method;
    const formData = new FormData(form);

    // post the data to the server to generate the PublicKeyCredentialCreateOptions
    let credentialCreateOptionsFromServer;
    try {
        credentialCreateOptionsFromServer = await submitForm(url, method, formData);
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

async function turn_off(form, event) {
    event.preventDefault();
    const timeout = form.dataset.timeout;
    const url = form.action;
    const response = await fetch(url);
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

async function turn_on(form, event) {
    event.preventDefault();
    const url = form.action;
    const response = await fetch(url);
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

async function webauthn_login(form) {
    // gather the data in the form
    const url = form.action;
    const method = form.method;
    const formData = new FormData(form);

    // post the login data to the server to retrieve the PublicKeyCredentialRequestOptions
    let credentialCreateOptionsFromServer;
    try {
        credentialRequestOptionsFromServer = await submitForm(url, method, formData);
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

async function loginClickHandler(manage, form, event) {
    event.preventDefault();
    const transformedAssertionForServer = await webauthn_login(form);
    try {
        await postAssertionToServer(transformedAssertionForServer, manage);
    } catch (err) {
        return console.error("Error when validating assertion on server:", err);
    }
}

async function registerClickHandler(form, event) {
    event.preventDefault();
    const newAssertionForServer = await webauthn_register(form);
    let assertionValidationResponse;
    try {
        assertionValidationResponse = await postNewAssertionToServer(newAssertionForServer);
        window.location.href = document.getElementById('manage-url').href;
    } catch (err) {
        alert("Registration failed.")
        return console.error("Server validation of credential failed:", err);
    }
}

/**
 * Posts the new credential data to the server for validation and storage.
 * @param {Object} credentialDataForServer
 */
async function postNewAssertionToServer(credentialDataForServer) {
    const formData = new FormData();
    Object.entries(credentialDataForServer).forEach(([key, value]) => {
        formData.set(key, value);
    });

    return await fetch_json(
        document.getElementById('verify-url').href, {
            method: "POST",
            body: formData
        });
}

async function newRegisterClickHandler(form, event) {
    event.preventDefault();
    const newAssertionForServer = await webauthn_register(form);
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
function transformAssertionForServer(newAssertion) {
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
}

/**
 * Post the assertion to the server for validation and logging the user in.
 * @param {Object} assertionDataForServer
 */
async function postAssertionToServer(assertionDataForServer, manage) {
    const formData = new FormData();
    Object.entries(assertionDataForServer).forEach(([key, value]) => {
        formData.set(key, value);
    });

    var result = await fetch_text1(
        document.getElementById('assertion-url').href, {
            method: "POST",
            body: formData
        }, manage);
    return result
}
/**
 * Posts the new credential data to the server for validation and storage.
 * @param {Object} credentialDataForServer
 */
async function postTotallyNewAssertionToServer(credentialDataForServer) {
    const formData = new FormData();
    Object.entries(credentialDataForServer).forEach(([key, value]) => {
        formData.set(key, value);
    });

    return await fetch_text(
        document.getElementById('verify-url').href, {
            method: "POST",
            body: formData
        });
}

async function fetch_text(url, options) {
    const response = await fetch(url, options);
    var a = response.clone()
    var returned = ""
    a.text().then((x) => {
        window.location.href = document.getElementById('logout-url').href;
    })
    return returned
}


function deleteCredential(event) {
    event.preventDefault();
    const url = this.action;
    const method = this.method;
    fetch(url, {method: method}).finally(() => {
        setTimeout(location.reload.bind(location), 500);
    });
}

document.addEventListener("DOMContentLoaded", e => {
    const formIds = {
        'manage-form': loginClickHandler.bind(null, true),
        'login-form': loginClickHandler.bind(null, false),
        'turn_off_form': turn_off,
        'turn_on_form': turn_on,
        'new-register-form': newRegisterClickHandler,
        'register-form': registerClickHandler
    };
    for (const formId in formIds) {
        const form = document.getElementById(formId);
        if (form !== null) {
            form.addEventListener('submit', formIds[formId].bind(null, form));
        }
    }
    const formClasses = {
        'delete-form': deleteCredential
    };
    for (const formClass in formClasses) {
        const forms = Array.from(document.getElementsByClassName(formClass));
        forms.forEach((form) => {
            form.addEventListener('submit', formClasses[formClass]);
        });
    }
});

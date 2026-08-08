function submit_secret_credentials() {
    // Credentials are never embedded in client side script. Obfuscating them only hides
    // them from a casual reader: anyone can read the source or watch the request and
    // recover them. The browser now triggers a server side flow that holds no secret.
    var xhttp = new XMLHttpRequest();
    xhttp.open('POST', 'InsecureLogin/login', true);
    xhttp.send();
}

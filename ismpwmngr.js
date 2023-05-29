document.body.style.border = "5px solid red";

var bootstrapCSS = document.createElement('link');
bootstrapCSS.rel = 'stylesheet';
bootstrapCSS.href = chrome.runtime.getURL('./bootstrap-4/css/bootstrap.min.css');
document.head.appendChild(bootstrapCSS);

var popupType = null;
var passphrase = null;
var pressedInput = null;

// Get all inputs(except type=hidden) from the page
const inputs = Array.from(document.getElementsByTagName("input"));
for (let i = 0; i < inputs.length; i++) {
    
    if (inputs[i].type === "hidden") {
    
    inputs.splice(i, 1);
    i--; // decrease the index since we just removed an element
    }
}
console.log(inputs); //debug purposes

// Loop through all inputs and find the email, username, and password inputs
for (let i = 0; i < inputs.length; i++) {
    
    const type = inputs[i].getAttribute("type");
    if (type === "email") {
    var emailInput = inputs[i];
    } else if (type === "text" && (inputs[i].getAttribute("name").includes("login") || inputs[i].getAttribute("name").includes("username") || inputs[i].getAttribute("name").includes("user") || inputs[i].getAttribute("name").includes("account"))) {
    var textInput = inputs[i];
    } else if (type === "password") {
    var passwordInput = inputs[i];
    }
}

var popup = null; 
var encCreds = null;
// Get credentials from credentials.json
fetch(chrome.runtime.getURL('credentials.json'))
  .then(response => response.json())
  .then(data => {
    encCreds = data;
  })
  .catch(error => {
    console.error('Error:', error);
  });

console.log("popup script loaded");

// Add onclick event handler to the input fields
try {
    emailInput.addEventListener("click", function() {
        
        console.log("email field clicked");
        pressedInput = emailInput;

        if (encCreds.bearer == null && popupType != 'auth') {
          popup = createAuthPopup();
          popupType = 'auth';
        } else if(popupType != 'suggestion') {
          popup = createSuggestionPopup();
          popupType = 'suggestion';
        }

        try{
            textInput.removeChild(popup);
        } catch {}
        try {
            passwordInput.removeChild(popup);
        } catch {}
        
        addPopup(emailInput, popup);
    });
} catch {
    console.error("Email input field not found");
}
try {
    textInput.addEventListener("click", function() {
        
        console.log("text field clicked");
        pressedInput = textInput;
        
        if (encCreds.bearer == null && popupType != 'auth') {
          popup = createAuthPopup();
          popupType = 'auth';
        } else if(popupType != 'suggestion') {
          popup = createSuggestionPopup();
          popupType = 'suggestion';
        }

        try {
            emailInput.removeChild(popup);
        } catch {}
        try {  
            passwordInput.removeChild(popup);
        } catch {}
        addPopup(textInput, popup);
    });
} catch {
    console.error("Text input field not found");
}
try {
    passwordInput.addEventListener("click", function() {
        
        console.log("password field clicked");
        pressedInput = passwordInput;

        if (encCreds.bearer == null && popupType != 'auth') {
          popup = createAuthPopup();
          popupType = 'auth';
        } else if(popupType != 'suggestion') {
          popup = createSuggestionPopup();
          popupType = 'suggestion';
        }

        try {
            emailInput.removeChild(popup);
        } catch {}
        try {
            textInput.removeChild(popup);
        } catch {}
        addPopup(passwordInput, popup);
    });
} catch {
    console.error("Password input field not found");
}

// Add click event listener to the document to hide the popup when the user clicks outside of the input field
document.addEventListener('click', function(event) {
  
    const clickedElement = event.target;
  // Check if the clicked element is an input field or its parent
  if (!clickedElement.closest('input')) {
    // Click occurred outside of any input field, hide the popup
    popup.style.display = 'none';
  } else {
    // Click occurred inside of an input field, show the popup
    popup.style.display = 'block';
  }
});


function createAuthPopup() {

    // Create a new element for the popup
    var popup = document.createElement("div");

    // Set the CSS styles for the popup
    popup.style.position = "absolute";
    popup.style.backgroundColor = "rgba(0, 0, 0, 0.8)";
    popup.style.display = "flex";
    popup.style.justifyContent = "center";
    popup.style.alignItems = "center";
    popup.style.borderRadius = "5px";
    popup.style.border = "2px solid black";
    popup.style.display = "none";

    // Create a new element for the text inside the popup
    var passphraseDiv = document.createElement("div");
    passphraseDiv.setAttribute("class", "text-info py-1");
    var passphraseLabel = document.createElement("label");
    passphraseLabel.textContent = "Passphrase for suggestions:";
    passphraseLabel.setAttribute("for", "passphrase");
    passphraseLabel.style.textAlign = "center";

    var passphraseInput = document.createElement("input");
    passphraseInput.setAttribute("type", "password");
    passphraseInput.setAttribute("id", "passphrase");
    passphraseInput.setAttribute("autocomplete", "off");
    passphraseInput.setAttribute("class", "form-control form-control-sm bg-dark text-light"); 
    passphraseInput.style.backgroundColor = "white";
    passphraseInput.style.width = "80%"
    passphraseInput.style.margin = "auto";
    passphraseInput.style.textAlign = "center";

    var sendButton = document.createElement("button");
    sendButton.textContent = "Auth";
    sendButton.setAttribute("type", "button");
    sendButton.setAttribute("class", "btn btn-outline-info btn-sm btn-block mt-1 pb-1");
    sendButton.style.width = "80%";
    sendButton.style.margin = "auto";

    // Add an event listener to the button
    sendButton.addEventListener("click", function() {

        console.log("Authenticating...");
        passphrase = passphraseInput.value;
        doAuth(passphrase);
    });



    passphraseDiv.appendChild(passphraseLabel);
    passphraseDiv.appendChild(passphraseInput);
    passphraseDiv.appendChild(sendButton);

    // Add the element to the popup
    popup.appendChild(passphraseDiv);

    return popup;
}

function createSuggestionPopup() {

    // Create a new element for the popup
    var popup = document.createElement("div");

    // Set the CSS styles for the popup
    popup.style.position = "absolute";
    popup.style.backgroundColor = "rgba(0, 0, 0, 0.7)";
    popup.style.display = "flex";
    popup.style.justifyContent = "center";
    popup.style.alignItems = "center";
    popup.style.borderRadius = "5px";
    popup.style.border = "2px solid black";
    popup.style.display = "none";

    // Create a new element for the content inside the popup

    var container = document.createElement("div");
    container.setAttribute("class", "container-fluid");

    var containerLabel = document.createElement("div");
    containerLabel.setAttribute("class", "row");
    var containerLabelText = document.createElement("div");
    containerLabelText.setAttribute("class", "pt-2 col-12 text-info text-center");
    containerLabelText.textContent = "Suggestions";
    containerLabel.appendChild(containerLabelText);
    container.appendChild(containerLabel);

    var accountSegment = document.createElement("div");
    accountSegment.setAttribute("id", "account-segment");
    var accountSegmentRow = document.createElement("div");
    accountSegmentRow.setAttribute("class", "row");
    var accountSegmentWebsite = document.createElement("div");
    accountSegmentWebsite.setAttribute("class", "d-flex flex-row");
    var accountSegmentWebstieLabel = document.createElement("div");
    accountSegmentWebstieLabel.setAttribute("class", "ml-3 mt-4 p-2 text-info");
    const url = window.location.href;
    const startIndex = url.indexOf("//") + 2; // Find the index after the double slashes
    const endIndex = url.indexOf("/", startIndex); // Find the index of the next forward slash
    const domain = url.substring(startIndex, endIndex);
    accountSegmentWebstieLabel.textContent = "Website:";
    var accountSegmentWebsiteContent = document.createElement("div");
    accountSegmentWebsiteContent.setAttribute("id", "current-website");
    accountSegmentWebsiteContent.setAttribute("class", "mt-4 p-2 text-muted");
    accountSegmentWebsiteContent.textContent = domain;
    accountSegmentWebsite.appendChild(accountSegmentWebstieLabel);
    accountSegmentWebsite.appendChild(accountSegmentWebsiteContent);
    accountSegmentRow.appendChild(accountSegmentWebsite);

    var accountSegmentSuggestions = document.createElement("div");
    accountSegmentSuggestions.setAttribute("class", "row");
    var accountSegmentSuggestionsMarginLeft = document.createElement("div");
    accountSegmentSuggestionsMarginLeft.setAttribute("class", "col-1");
    accountSegmentSuggestions.appendChild(accountSegmentSuggestionsMarginLeft);

    var accountSegmentSuggestionsContent = document.createElement("div");
    accountSegmentSuggestionsContent.setAttribute("class", "col-10 pb-4 list-group list-group-flush bg-transparent");
    var accountSegmentSuggestionsContentList = getAccountSuggestions(domain, passphrase);
    accountSegmentSuggestionsContent.appendChild(accountSegmentSuggestionsContentList);
    accountSegmentSuggestions.appendChild(accountSegmentSuggestionsContent);

    var accountSegmentSuggestionsMarginRight = document.createElement("div");
    accountSegmentSuggestionsMarginRight.setAttribute("class", "col-1");
    accountSegmentSuggestions.appendChild(accountSegmentSuggestionsMarginRight);

    accountSegmentRow.appendChild(accountSegmentSuggestions);
    accountSegment.appendChild(accountSegmentRow);
    container.appendChild(accountSegment);

    return container;
}

function doAuth(passPhrase) {

  basicToken = "Basic " + btoa(decrypt(passPhrase, encCreds.clientId) + ":" + decrypt(passPhrase, encCreds.clientSecret));
  console.log("Basic token: " + basicToken);

  var myHeaders = new Headers();
  myHeaders.append("grant_type", "CLIENT_CREDENTIALS");
  myHeaders.append("Content-Type", "application/json");
  myHeaders.append("Authorization", basicToken);
  
  var raw = JSON.stringify({
      "passphrase": passPhrase
  });

  var requestOptions = {
      method: 'POST',
      headers: myHeaders,
      body: raw,
      redirect: 'follow'
  };

  fetch("https://password-manager-api.us-e2.cloudhub.io/v1/actions/auth", requestOptions)
  .then(response => response.text())
  .then(result => encCreds.bearer = JSON.parse(result).data.access_token).then(() => console.log("Bearer token: " + encCreds.bearer))
  .catch(error => console.log('error: ' + error));
}

function getAccountSuggestions(domain, passphrase) {

  var accountSegmentSuggestionsContentList = document.createElement("ul");
  accountSegmentSuggestionsContentList.setAttribute("id", "account-suggestions-list");

  // Get accounts suggestions based on the current URL
  var bearerToken = "Bearer " + encCreds.bearer;
  var requestUrl = "https://password-manager-api.us-e2.cloudhub.io/v1/accounts?domain=" + domain;
  var myHeaders = new Headers();
  myHeaders.append("Authorization", bearerToken);

  var requestOptions = {
    method: 'GET',
    headers: myHeaders,
    redirect: 'follow'
  };

  fetch(requestUrl, requestOptions)
    .then(response => response.text())
    .then(result => JSON.parse(result).data.forEach(element => {

      var li = document.createElement("li");
      li.setAttribute("class", "list-group-item list-group-item-action bg-transparent");
      li.textContent = decrypt(decrypt(passphrase, encCreds.clientSecret), element.username);

      li.addEventListener("click", function() {

        console.log("List item clicked: " + li.textContent);
        if(pressedInput.getAttribute("type") == "text" || pressedInput.getAttribute("type") == "email") {

          pressedInput.value = li.textContent;
        } 
        if(passwordInput != null) {

          passwordInput.value = decrypt(decrypt(passphrase, encCreds.clientSecret), element.password);
        }
      });

      accountSegmentSuggestionsContentList.appendChild(li);
    }))
    .catch(error => console.log('error', error));

    return accountSegmentSuggestionsContentList;
}

function addPopup(input, popup) {
  const inputWidth = input.offsetWidth;
  const inputHeight = input.offsetHeight;
  popup.style.width = inputWidth + "px";
  popup.style.top = (input.offsetTop - inputHeight) - 70 + "px";
  input.parentNode.insertBefore(popup, input);
  console.log(input.getAttribute("type") + " input found!");
}


// crypto functions
function generateKey(salt, passPhrase) {
  return CryptoJS.PBKDF2(passPhrase, CryptoJS.enc.Hex.parse(salt), {
  keySize: 256 / 32,
  iterations: 1989
  })
}

function encryptWithIvSalt(salt, iv, passPhrase, plainText) {
  let key = generateKey(salt, passPhrase);
  let encrypted = CryptoJS.AES.encrypt(plainText, key, {
  iv: CryptoJS.enc.Hex.parse(iv)
  });
  return encrypted.ciphertext.toString(CryptoJS.enc.Base64);
}

function decryptWithIvSalt(salt, iv, passPhrase, cipherText) {
  let key = generateKey(salt, passPhrase);
  let cipherParams = CryptoJS.lib.CipherParams.create({
  ciphertext: CryptoJS.enc.Base64.parse(cipherText)
  });
  let decrypted = CryptoJS.AES.decrypt(cipherParams, key, {
  iv: CryptoJS.enc.Hex.parse(iv)
  });
  return decrypted.toString(CryptoJS.enc.Utf8);
}

function encrypt(passPhrase, plainText) {
  let iv = CryptoJS.lib.WordArray.random(128 / 8).toString(enc.Hex);
  let salt = CryptoJS.lib.WordArray.random(256 / 8).toString(enc.Hex);
  let ciphertext = encryptWithIvSalt(salt, iv, passPhrase, plainText);
  return salt + iv + ciphertext;
}

function decrypt(passPhrase, cipherText) {
  let ivLength = 128 / 4;
  let saltLength = 256 / 4;
  let salt = cipherText.substr(0, saltLength);
  let iv = cipherText.substr(saltLength, ivLength);
  let encrypted = cipherText.substring(ivLength + saltLength);
  return decryptWithIvSalt(salt, iv, passPhrase, encrypted);
}

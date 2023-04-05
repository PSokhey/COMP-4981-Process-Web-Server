const postButton = document.getElementById('post-button');
const getButton = document.getElementById('get-button');
const deleteButton = document.getElementById('delete-button');
const outputDiv = document.getElementById('output');
const statusPopup = document.getElementById('status-popup');
const statusPopupContent = document.getElementById('status-popup-content');
const statusPopupClose = document.getElementById('status-popup-close');

function showStatusPopup(statusCode, message, success = true) {
    statusPopupContent.textContent = `${statusCode}: ${message}`;
    statusPopupContent.style.backgroundColor = success ? 'green' : 'red';
    statusPopup.style.display = 'block';
}

statusPopupClose.addEventListener('click', () => {
    statusPopup.style.display = 'none';
});

// Send a POST request to the server
function postData() {
    const keyInput = document.getElementById('key-input');
    const inputBox = document.getElementById('input-box');
    const data = { key: keyInput.value, message: inputBox.value };

    fetch(window.location.href, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    })
        .then(response => {
            if (response.ok) {
                showStatusPopup(response.status, 'Data posted successfully!', true);
            } else {
                showStatusPopup(response.status, 'An error occurred while posting data.', false);
            }
            return response.json();
        })
        .then(response => console.log(response))
        .catch(error => console.error(error));
}

// Send a GET request to the server
function getData() {
    const baseUrl = window.location.href.split('/')[0]; // get the base URL
    fetch(baseUrl + 'getDatabase') // use the base URL for the request
        .then(response => {
            if (response.ok) {
                showStatusPopup(response.status, 'Data fetched successfully!', true);
            } else {
                showStatusPopup(response.status, 'An error occurred while fetching data.', false);
            }
            return response.text();
        })
        .then(data => {
            console.log(data);
            // Split the data string using the separator and join with HTML line break tag
            const formattedData = data.split('||').join('<br><br>');
            outputDiv.innerHTML = formattedData;
        })
        .catch(error => console.error(error));
}

// Send a DELETE request to the server
function deleteData() {
    fetch(window.location.href + 'DELETE', {
        method: 'DELETE'
    })
        .then(response => {
            if (response.ok) {
                showStatusPopup(response.status, 'Database deleted successfully!', true);
                outputDiv.innerHTML = '';
            } else {
                showStatusPopup(response.status, 'An error occurred while deleting the database.', false);
            }
            return response.json();
        })
        .then(response => console.log(response))
        .catch(error => console.error(error));
}

postButton.addEventListener('click', postData);
getButton.addEventListener('click', getData);
deleteButton.addEventListener('click', deleteData);

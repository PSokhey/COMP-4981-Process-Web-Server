const postButton = document.getElementById('post-button');
const getButton = document.getElementById('get-button');
const outputDiv = document.getElementById('output');

// Define the URL of the server
const url = '192.168.0.74:8080';

// Send a POST request to the server
function postData() {
  const inputBox = document.getElementById('input-box');
  const data = { message: inputBox.value };

  fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(data)
  })
  .then(response => response.json())
  .then(response => {
    console.log(response);
    outputDiv.innerHTML = 'Data posted successfully!';
  })
  .catch(error => console.error(error));
}

// Send a GET request to the server
function getData() {
  fetch(url + '/getDatabase')
  .then(response => response.json())
  .then(data => {
    console.log(data);
    outputDiv.innerHTML = JSON.stringify(data);
  })
  .catch(error => console.error(error));
}

postButton.addEventListener('click', postData);
getButton.addEventListener('click', getData);


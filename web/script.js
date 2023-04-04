const postButton = document.getElementById('post-button');
const getButton = document.getElementById('get-button');
const deleteButton = document.getElementById('delete-button');
const outputDiv = document.getElementById('output');

// Send a POST request to the server
function postData() {
  const inputBox = document.getElementById('input-box');
  const data = { message: inputBox.value };

  fetch(window.location.href, {
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
  const baseUrl = window.location.href.split('/')[0]; // get the base URL
  fetch(baseUrl + 'getDatabase') // use the base URL for the request
      .then(response => response.text())
      .then(data => {
        console.log(data);
        outputDiv.innerHTML = data;
      })
      .catch(error => console.error(error));
}

// Send a DELETE request to the server
function deleteData() {
  fetch(window.location.href + 'DELETE', {
    method: 'DELETE'
  })
      .then(response => response.json())
      .then(response => {
        console.log(response);
        outputDiv.innerHTML = 'Database deleted successfully!';
      })
      .catch(error => console.error(error));
}

postButton.addEventListener('click', postData);
getButton.addEventListener('click', getData);
deleteButton.addEventListener('click', deleteData);


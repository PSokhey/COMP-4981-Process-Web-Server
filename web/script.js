const postButton = document.getElementById('post-button');
const getButton = document.getElementById('get-button');
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
  fetch(window.location.href + 'getDatabase')
  .then(response => response.text()) // receive response as text
  .then(data => {
    console.log(data);
    outputDiv.innerHTML = data; // print received data as a string
  })
  .catch(error => console.error(error));
}


postButton.addEventListener('click', postData);
getButton.addEventListener('click', getData);


// Setup of Datatable
$(document).ready(function () {
  $('#tableData').DataTable({
    paging: false,
    language: {
      info: '_TOTAL_ items',
    },
    order: [[2, 'asc']],
    columnDefs: [
      {
        targets: [0, 1, 5],
        orderable: false,
      },
    ],
  });
});

// Checkbox handling
var checkboxes = document.querySelectorAll('.downloadBulkCheckbox');

Array.prototype.forEach.call(checkboxes, function (cb) {
  cb.addEventListener('change', function () {
    checkedBoxes = document.querySelectorAll(
      'input[type=checkbox]:checked'
    ).length;
    if (checkedBoxes >= 1) {
      document.getElementById('downloadBulkButton').style.display = 'block';
    } else {
      document.getElementById('downloadBulkButton').style.display = 'none';
    }
  });
});

function selectAll() {
  Array.prototype.forEach.call(checkboxes, function (cb) {
    cb.checked = true;
  });
  document.getElementById('downloadBulkButton').style.display = 'block';
}

function selectNone() {
  Array.prototype.forEach.call(checkboxes, function (cb) {
    cb.checked = false;
  });
  document.getElementById('downloadBulkButton').style.display = 'none';
}

var wsURL = '';
location.protocol !== 'https:'
  ? (wsURL = 'ws://' + window.location.host + '/?ws')
  : (wsURL = 'wss://' + window.location.host + '/?ws');
var connection = new WebSocket(wsURL);

connection.onopen = function () {
  console.log('Connected via WebSockets');
};

connection.onclose = function () {
  console.log('Connection has been closed by WebSocket Server');
};

connection.onerror = function (e) {
  console.log('Websocket error: ', e);
};

connection.onmessage = function (m) {
  try {
    var message = JSON.parse(m.data);
    if (message['type'] == 'refreshClipboard') {
      location.reload();
    } else if (message['type'] == 'updateCLI') {
      output = document.getElementById('cliOutput');
      output.innerHTML = message['content'];
      input = document.getElementById('cliCommand');
      input.value = '';
    }
  } catch (e) {
    console.log('Error reading message: ', e);
  }
};

function sendEntry(e) {
  e.preventDefault();
  entryfield = document.getElementById('cbEntry');
  var text = entryfield.value;
  var msg = {
    type: 'newEntry',
    content: text,
  };
  connection.send(JSON.stringify(msg));
  entryfield.value = '';
}

function clearClipboard(e) {
  e.preventDefault;
  result = confirm('Are you sure you want to clear the clipboard?');
  if (result) {
    var msg = {
      type: 'clearClipboard',
      content: '',
    };
    connection.send(JSON.stringify(msg));
  }
}

function delClipboard(id) {
  var msg = {
    type: 'delEntry',
    content: id,
  };
  connection.send(JSON.stringify(msg));
}

function sendCommand(e) {
  e.preventDefault();
  command = document.getElementById('cliCommand');
  var text = command.value;
  var msg = {
    type: 'command',
    content: text,
  };
  connection.send(JSON.stringify(msg));
  command.value == '';
  command.focus();
}

$('#cliCommand').on('keydown', function (e) {
  if (e.which == 13) {
    sendCommand(e);
  }
});

function copyToClipboard(id) {
  let textSelected = document
    .getElementById('card-body-' + id)
    .getElementsByTagName('pre')[0].innerText;

  navigator.clipboard.writeText(textSelected);
}

function hello() {
	alert('hello');
	
	
	//document.getElementsByTagName('form')[0].message_body.value = 'hello!!';
	
	alert("submitted!");
}
//this works
function encryptAndSubmit() {
	var button = document.getElementById('encryptButton');
	document.getElementById('encryptButton').click();
	document.getElementsByTagName('form')[0].commit.click();
}


function readPrivateAndDecrypt() {
	startPriRead();
	// this could look funky, but it doesnt work without this delay function
	setTimeout(function() { document.getElementById('decryptButton').click();},1000);
}
function readPublicAndSubmit() {
	startPubRead();
	//document.getElementById('encryptAndSubmitButton').click();	
	//setTimeout(function() { document.getElementById('encryptButton').click();},10);
	//setTimeout(function() document.getElementsByTagName('form')[0].commit.click();},20);
	
}

function trim(msg) {
	return msg.replace(/[\s\r\t\n]/g, '');
}

function disableEnterKey(e)
{
     var key;
     if(window.event)
          key = window.event.keyCode;     //IE
     else
          key = e.which;     //firefox
     if(key == 13)
          return false;
     else
          return true;
}

function encryptMsg() {
  document.getElementsByTagName('form')[0].message_body.value = window.document.theForm.input.value;
  encryptAndSubmit();
}

function decrypt() {
	var oTable = document.getElementById('messages');
    //gets table

    var rowLength = oTable.rows.length;
    //gets rows of ta
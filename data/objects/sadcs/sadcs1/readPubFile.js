function startPubRead()
{
  // obtain input element through DOM 

  var file = document.getElementById('public_key_file').files[0];
  if(file)
	{
    pubgetAsText(file);
  }
}

function pubgetAsText(readFile)
{
	var reader;
	try
	{
    reader = new FileReader();
	}catch(e)
	{
		document.getElementById('public_key').innerHTML =
			"Error: seems File API is not supported on your browser";
	  return;
  }

  // Read file into memory as UTF-8
  reader.readAsText(readFile, "UTF-8");

  // Handle progress, success, and errors
  reader.onload = publoaded;
  reader.onerror = puberrorHandler;
}


function publoaded(evt)
{
  // Obtain the read file data
  var fileString = evt.target.result;
  public_key_1024 = fileString;
    document.getElementById("pubgood").innerHTML = "<img src='images/greencheck.jpeg' />";

}

function puberrorHandler(evt)
{
  if(evt.target.error.code == evt.target.error.NOT_READABLE_ERR)
	{
    // The file could not be read
		document.getElementById('public_key').innerHTML = "Error reading file..."
  }
}

var public_key_1024;
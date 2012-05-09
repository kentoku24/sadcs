function startPriRead()
{
  // obtain input element through DOM 

  var file = document.getElementById('private_key_file').files[0];
  if(file)
	{
    prigetAsText(file);
  }
}

function prigetAsText(readFile)
{
	var reader;
	try
	{
    reader = new FileReader();
	}catch(e)
	{
		document.getElementById('private_key').innerHTML =
			"Error: seems File API is not supported on your browser";
	  return;
  }

  // Read file into memory as UTF-8
  reader.readAsText(readFile, "UTF-8");

  // Handle progress, success, and errors
  reader.onload = priloaded;
  reader.onerror = prierrorHandler;
}


function priloaded(evt)
{
  // Obtain the read file data
  var fileString = evt.target.result;
  private_key_1024 = fileString;
  document.getElementById("prigood").innerHTML = "<img src='images/greencheck.jpeg' />";
}

function prierrorHandler(evt)
{
  if(evt.target.error.code == evt.target.error.NOT_READABLE_ERR)
	{
    // The file could not be read
		document.getElementById('private_key').innerHTML = "Error reading file..."
  }
}

var private_key_1024;
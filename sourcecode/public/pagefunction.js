// JavaScript Document
function formatString(str)
{
  var tmp='';
  for(var i=0;i<str.length;i+=80)
    tmp += '   ' + str.substr(i,80) +'\n';
  return tmp;
}
 
function showData(tree) {
  var data = '';
  var val = '';
  if(tree.value)
   val = tree.value;
  data += tree.type + ':' +  val.substr(0,48) + '...\n';
  if(tree.sub)
    for(var i=0;i<tree.sub.length;i++)
      data += showData(tree.sub[i]);
  return data;
}
 
function certParser(cert){
  var lines = cert.split('\n');
  var read = false;
  var b64 = false;
  var end = false;
  var flag = '';
  var retObj = {};
  retObj.info = '';
  retObj.salt = '';
  retObj.iv;
  retObj.b64 = '';
  retObj.aes = false;
  retObj.mode = '';
  retObj.bits = 0;
  for(var i=0; i< lines.length; i++){
    flag = lines[i].substr(0,9);
    if(i==1 && flag != 'Proc-Type' && flag.indexOf('M') == 0)//unencrypted cert?
      b64 = true;
    switch(flag){
      case '-----BEGI':
        read = true;
        break;
      case 'Proc-Type':
        if(read)
          retObj.info = lines[i];
        break;
      case 'DEK-Info:':
        if(read){
          var tmp = lines[i].split(',');
          var dek = tmp[0].split(': ');
          var aes = dek[1].split('-');
          retObj.aes = (aes[0] == 'AES')?true:false;
          retObj.mode = aes[2];
          retObj.bits = parseInt(aes[1]);
          retObj.salt = tmp[1].substr(0,16);
          retObj.iv = tmp[1];
        }
        break;
      case '':
        if(read)
          b64 = true;
        break;
      case '-----END ':
        if(read){
          b64 = false;
          read = false;
        }
      break;
      default:
        if(read && b64)
          retObj.b64 += pidCryptUtil.stripLineFeeds(lines[i]);
    }
  }
  return retObj;
}
 
function compute(mode, msg){
 
 // var hexStr = 'A3C9D10BDDC14811BC92E2D29282F62F1E449E2DD9B9CE3CA74D637ADAD49778BFEA4ACEE58C146E73E579876422871F625C8B0D2202131003C5A6C14F03493DB785B66A450A3418B2DC332A4A35AF7C89549B9902B2813CF79749198610F651ED33BE4C8B5753695F6D3461414C85C9237E67BB69A8A057A4841445A56955FA55ED27895A27FEB8A31453C6DE0B44259214AF1E23AA8011D68D2B115EE0D912B8E9C8F49D6A46685E778AC867BDD0361A52A7CE2F98702689D11E3BFB3746AB1F36F35033DA5FC38CA8F50178F6D2B37C39EEDABEF10FC0FD33E8FCED5A1D2677067B375DA83C9A8344391889FEE7B1BFC1282125563B3EDE479D4AD78CCF1F';
 
 // alert(hex2b64(hexStr) + '\n' + pidCryptUtil.encodeBase64(pidCryptUtil.convertFromHex(hexStr)));
 
  var theForm = window.document.theForm;
  var input = document.getElementsByTagName('form')[0].message_body.value;
  var crypted = msg;
  var public_key = public_key_1024;
  var private_key = private_key_1024;
  var params = {};
  var result = '';

  //read cert
  switch(mode){
    case 'encrypt':
      params = certParser(public_key);
      if(params.b64){
        var key = pidCryptUtil.decodeBase64(params.b64);
        //new RSA instance
        var rsa = new pidCrypt.RSA();
        //RSA encryption
        //ASN1 parsing
        var asn = pidCrypt.ASN1.decode(pidCryptUtil.toByteArray(key));
        var tree = asn.toHexTree();
        //setting the public key for encryption
        rsa.setPublicKeyFromASN(tree);
        var t = new Date();  // timer
        crypted = rsa.encrypt(input);
        
        document.getElementsByTagName('form')[0].message_body.value  = pidCryptUtil.fragment(pidCryptUtil.encodeBase64(pidCryptUtil.convertFromHex(crypted)),64);
       } else alert('Could not find public key.');
     break;
   case 'decrypt':
     params = certParser(private_key);
     if(params.b64){
        key = pidCryptUtil.decodeBase64(params.b64);
        var rsa = new pidCrypt.RSA();
        //RSA decryption
        //ASN1 parsing
        asn = pidCrypt.ASN1.decode(pidCryptUtil.toByteArray(key));
        tree = asn.toHexTree();
        //alert(showData(tree));
        //setting the private key for encryption
        rsa.setPrivateKeyFromASN(tree);
        t = new Date();  // timer
        crypted = pidCryptUtil.decodeBase64(pidCryptUtil.stripLineFeeds(crypted));
        var decrypted = rsa.decrypt(pidCryptUtil.convertToHex(crypted));
        var result =  decrypted;
        return result;
      }  else alert('Could not find private key.');
    break;
  }
}



/*********************************************************************************************
**********************************************************************************************
*************    Items from Localfunctions         *******************************************
**********************************************************************************************
*********************************************************************************************/


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


function encryptMsg() {
  var file = document.getElementById('public_key_file').files[0];
  if (file == null) {
    alert("No Key");
  } else {
    document.getElementsByTagName('form')[0].message_body.value = window.document.theForm.input.value;
    encryptAndSubmit();
  }
}

function decrypt() {
	var oTable = document.getElementById('messages');
    //gets table

    var rowLength = oTable.rows.length;
    //gets rows of table

    for (i = 0; i < rowLength; i+=2){
    //loops through rows

       var oCells = oTable.rows.item(i).cells;
       //gets cells of current row
       var cellLength = oCells.length;
           for(var j = 0; j < cellLength; j++){
           //loops through each cell in current row
              <!--get your cell info here-->
              var cellVal = oCells.item(j).innerHTML;
			  cellVal = trim(cellVal);
              oCells.item(j).innerHTML = compute('decrypt', cellVal);
           }
    }
}

/*********************************************************************************************
**********************************************************************************************
***************************  Items from readPubFile    ***************************************
**********************************************************************************************
*********************************************************************************************/

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


/*********************************************************************************************
**********************************************************************************************
********************************   Items from readPriFile   **********************************
**********************************************************************************************
*********************************************************************************************/

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


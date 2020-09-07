<?php 
error_reporting(E_ALL);
//*desc: extracts the TX public key from the TX.Extra data
//*extra: TX.Extra field to extract the pubkey from
require_once('./lib/config.php');
require_once('./lib/helper.php');

$params = array(
    "extra" => $_GET["extra"],
);

$response=array(
	"id"=>0,
	"jsonrpc"=>"2.0"
);

function _rpc_error($data){
	$response["error"]=array("code"=>-32602,
	"message"=>"invalid parameters received",
	"data"=>$data
	);
	echo json_encode($response);
	exit(0);
}

/*
* The rpc call is removed from daemon so we implement it locally
*/
/*f(x:string[hex])=string:bin*/
$converted=hex2bin($params["extra"]);
/*f(x:string[bin])=N(array<string>)*/
$_len=strlen($converted);
/*f(x:string[bin])=array<string>*/
$converted=str_split($converted);
/*f(x:array<string>)=array<int>*/
$converted=array_map("ord",$converted);
//setup counters
$i=0;
$_txpub=array();
while($i<$_len){
	//*($converted)->$_tag
	$tag=$converted[$i];
	switch($tag){
		case 0x00:{
		//padding
		if($_len-$i+1<=255){
		//allow it
		//terminate the loop
		$i=$_len;
		break;
		}
		else{
		_rpc_error("padding");
		break;
		}
		}
		case 0x01:{
		//tx public key
		//assert($i+1+32<$_len)
		if($i+32>=$_len){
		_rpc_error("public key length");
		break;
		}
		else{
		//$converted[$i+1->$t+32]->$_txpub
		$_txpub=array_slice($converted,$i+1,32);
		$i+=33; 
		break; //complete
		}
		}
		case 0x02:{
		$_size=$converted[++$i];
		//we do nothing with it but we check it for security
		if($i+$_size>=$_len){
			_rpc_error("invalid extra nonce");
			break;
		}
		else{$i+=$_size+1;break;}
		}
		default:
			_rpc_error("invalid tag ".$tag);
	}
}
if(count($_txpub)!=32){
	_rpc_error("assert:83");
	exit(-1);
}
$response["result"]=array(
"pubkey"=>bin2hex(join("",array_map("chr",$_txpub)))
);
echo json_encode($response);
?>
<html>
<head>
<title>Wifite Status</title>
<style type="text/css">

#status {
  float: right;
/*  width: 100px;*/
}
#ivsps {
  float: left;
  width: 225px;
}
</style>
<script src="jquery-1.5.1.min.js"></script>  
<script>
$(document).ready(function() {
	$("#status").load("status.php");
	$("#ivsps").load("ivsps.php");

    function updateStatus(){
	$("#status").load("status.php");
    }
    setInterval( "updateStatus()", 5000);
    function updateIVsps(){
	$("#ivsps").load("ivsps.php");
    }
    setInterval( "updateIVsps()", 5000);

});
</script>
</head>
<body>
<div id="ivsps"></div>
<br />
<div id="status"></div>
<br />

</body>
</html>

<html>
<head>
<title>Wifite Log</title>
<style type="text/css">
<!--
@import url("style.css");
@import url("jquery.tablesorter.pager.css");
-->
</style>
<script src="jquery-1.5.1.min.js"></script>  
<script src="jquery.tablesorter.min.js"></script>  
<script src="jquery.tablesorter.pager.js"></script>  
<script>
$(document).ready(function() {
	$("#status").load("status.php");
	//$("#log").load("log.php");

    //$("#hor-zebra").tablesorter(); 
    $("#hor-zebra").tablesorter({widthFixed: true, widgets: ['zebra']}).tablesorterPager({container: $("#pager")}); 
	function updateStatus(){
		$("#status").load("status.php");
	}
	setInterval( "updateStatus()", 5000);
});
</script>
</head>
<body>
<div id="log">
<?php include "log.php" ?>
</div>

<br />
<br />
<br />
<div id="status"></div>

</body>
</html>

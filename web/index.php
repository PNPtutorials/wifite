<html>
<head>
<title>Wifite Status</title>
<script src="jquery-1.5.1.min.js"></script>  
<script>
$(document).ready(function() {
    $("#ivsps").load("ivsps.php");
    $("#status").load("status.php");
    var refreshId = setInterval(function() {
        $("#ivsps").load('ivsps.php?randval='+ Math.random());
        $("#status").load('status.php?randval='+ Math.random());
    }, 3000);
    $.ajaxSetup({ cache: false });

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

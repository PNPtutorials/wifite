<!-- Table markup-->
<table id="hor-zebra" class="tablesorter">

	<!-- Table header -->

		<thead>
			<tr>
				<th scope="col" id="name">Name</th>
				<th scope="col" id="key">Key</th>
				<th scope="col" id="bssid">AP MAC (BSSID)</th>
				<th scope="col" id="timestamp">Time</th>
			</tr>
		</thead>

	<!-- Table footer -->

		<tfoot>
	        <tr>
				<td scope="col" id="name">Name</th>
				<td scope="col" id="key">Key</th>
				<td scope="col" id="bssid">AP MAC (BSSID)</th>
				<td scope="col" id="timestamp">Time</th>
	        </tr>
		</tfoot>

	<!-- Table body -->

		<tbody>

<?php
    error_reporting(E_ALL);

    date_default_timezone_set('America/Los_Angeles');
    include 'crud.class.php';

    $crud = new crud;
    $crud->dsn = "sqlite:../log.db";

    $records = $crud->rawSelect('SELECT DISTINCT essid,key,bssid,timestamp FROM log ORDER BY timestamp DESC');
    $rows = $records->fetchAll(PDO::FETCH_ASSOC);
    foreach($rows as $row)
    {
        print '<tr>';
        foreach($row as $fieldname=>$value)
        {
            if($fieldname == 'timestamp'){
                    print '<td>'.date("F j, Y, g:i a", $value).'</td>';
            }else{
                    print '<td>'.$value.'</td>';
            }

        }

        print '</tr>';
    }

?>
		</tbody>

</table>

<div id="pager" class="pager">
    <form>
        <img src="icons/first.png" class="first"/>
        <img src="icons/prev.png" class="prev"/>
        <input type="text" class="pagedisplay"/>
        <img src="icons/next.png" class="next"/>
        <img src="icons/last.png" class="last"/>
        <select class="pagesize">
            <option selected="selected"  value="10">10</option>
            <option value="20">20</option>
            <option value="30">30</option>
            <option  value="40">40</option>
        </select>
    </form>
</div>


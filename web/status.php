
<table id="">

	<!-- Table header -->

		<thead>
			<tr>
				<th scope="col" id="time">Time</th>
				<th scope="col" id="status">Status</th>
			</tr>
		</thead>

	<!-- Table footer -->

		<tfoot>
	        <tr>
	              <td></td>
	              <td></td>
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

    $records = $crud->rawSelect('SELECT timestamp, status FROM status ORDER BY timestamp DESC LIMIT 10');
    $rows = $records->fetchAll(PDO::FETCH_ASSOC);
    $odd = false;
    foreach($rows as $row)
    {
	if($odd){
	        print '<tr class="odd">';
	}else{
        	print '<tr>';
	}
	$odd = !$odd;
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

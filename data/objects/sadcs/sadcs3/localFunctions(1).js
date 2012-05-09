ble

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

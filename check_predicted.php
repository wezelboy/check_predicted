<?php
#
# Template for check_predicted.py nagios plugin
# Very roughly based on William Leibzon's check_memory plugin
# This currently is specific for Network Traffic, but I should rework for general case.
# 
# Heavily modified by Patrick Gavin 2013

$ds_name[1] = "Traffic Analysis";
$opt[1]  = " --vertical-label \"Traffic (bps)\" -b 1024 --title \"Outbound Traffic Analysis of $hostname\" ";

$def[1]  = "DEF:difference=$RRDFILE[1]:$DS[1]:AVERAGE " ;
$def[1] .= "DEF:measured=$RRDFILE[2]:$DS[2]:AVERAGE " ;
$def[1] .= "DEF:predicted=$RRDFILE[3]:$DS[3]:AVERAGE ";
$def[1] .= "DEF:sigma=$RRDFILE[4]:$DS[4]:AVERAGE ";

# Define CDEFs of the datasets
$def[1] .= "CDEF:diff_bits=difference ";
$def[1] .= "CDEF:meas_bits=measured ";
$def[1] .= "CDEF:pred_bits=predicted ";
$def[1] .= "CDEF:sig_bits=sigma ";

# Define upper and lower limits of confidence
$def[1] .= "CDEF:ulimit=sig_bits,pred_bits,+ ";
$def[1] .= "CDEF:llimit=pred_bits,sig_bits,- ";
$def[1] .= "CDEF:conf_rng=sig_bits,2,* ";

# Draw some graphs

$def[1] .= "AREA:llimit#F0819980:\"Area under limit of confidence\\n\" " ;
$def[1] .= "AREA:conf_rng#81F08380:\"Area within limit of confidence\\n\":STACK " ;

$def[1] .= "LINE:meas_bits#3C8EE6:\"Measured Outbound Traffic\:      \t\" " ;
$def[1] .= "GPRINT:meas_bits:LAST:\"%6.3lf %s\t\" " ;
$def[1] .= "GPRINT:meas_bits:MAX:\"Max\: %6.3lf %s\t\" " ;
$def[1] .= "GPRINT:meas_bits:AVERAGE:\"Average\: %6.3lf %s\t\"\l " ;

$def[1] .= "LINE:pred_bits#000000:\"Predicted Outbound Traffic\:      \t\" " ;
$def[1] .= "GPRINT:pred_bits:LAST:\"%6.3lf %s\t\" " ;
$def[1] .= "GPRINT:pred_bits:MAX:\"Max\: %6.3lf %s\t\" " ;
$def[1] .= "GPRINT:pred_bits:AVERAGE:\"Average\: %6.3lf %s\t\"\l " ;

$def[1] .= "AREA:diff_bits#FF0000:\"Anomalous Outbound Traffic\:      \t\" " ;
$def[1] .= "GPRINT:diff_bits:LAST:\"%6.3lf %s\t\" " ;
$def[1] .= "GPRINT:diff_bits:MAX:\"Max\: %6.3lf %s\t\" " ;
$def[1] .= "GPRINT:diff_bits:AVERAGE:\"Average\: %6.3lf %s\t\"\l " ;

?>


# check_predicted.py
# version 0.6
Nagios plugin that analyzes RRD files for real-time anomaly detection.

I'm currently reworking to run under check_mk/OMD in a more general case
since people seem to be interested in that sort of thing.

February 2020- check will run in omd environment. It will now alert on anomalies.
By default it will only return the difference/sigma ratio, but in debug mode it will
return all metrics.

Check should be run as OMD site user.

A simple example would be:
check_predicted.py --host $HOST --servicename Interface_1

check_predicted.php is a crude pnp4nagios template for graphing.
It is not updated.

Note: I keep my stuff in a private repo elsewhere. But I will make
occasional updates here.



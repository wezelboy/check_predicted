# check_predicted.py
# version 0.7
Nagios plugin that analyzes RRD files for real-time anomaly detection.

This plugin uses the nagios-plugin python module. You will need to install that.

This plugin is meant to run under check_mk/OMD in a more general case. To install,
put both python files in /opt/omd/sites/$sitename/local/lib/nagios/plugins

check_predicted.py uses the rrdtool PREDICTSIGMA tool to generate predictions of all
the performance metrics of a service. It then compares the predicted value to the
actual current value. The main output is the "difference/sigma ratio", which is the
difference between the actual and predicted value divided by the standard deviation.

The higher the d/s ratio, the more anomalous the actual value. The nagios warn and
crit values are compared to the d/s ratio.

By default it will only return the difference/sigma ratio, but in debug mode it will
return all metrics.

Check should be run as OMD site user. In check_mk it is meant to be run as an active
check. By default, there should be about 5 weeks of data to work with.

A simple example would be:
check_predicted.py --host $HOST --servicename Interface_1

Note: I keep my stuff in a private repo elsewhere. But I will make
occasional updates here.



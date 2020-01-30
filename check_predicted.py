#!/usr/bin/env python

# check_predicted.py
# check_predicted.py uses rrdtool's prediction functions to detect unusual behavior.
# It is primarily to be used for interface traffic, but hopefully it will find use in other data sets.
# Originally written by Patrick Gavin. March 2013
# Retooled for OMD/check-mk 2020
#
# check_predicted utilizes the google nagiosplugin class and also assumes an OMD environment.
# The --path argument can be used to point to a different rrd file location if necessary.
# I'm currently in the process of reworking it to run in a check_mk/OMD environment.


import sys
import os
import re
import argparse
import subprocess
import logging
import nagiosplugin
import time
import rrd_query
import datetime
import shelve

class MetricPredict(nagiosplugin.Resource):
    '''
    class MetricPredict looks at performance data rrds, makes a prediction on what the specified metric should
    be and then compares it to the current measurement of that metric.
    
    If the current measurement differs from the prediction by more than the standard deviation (sigma) multiplied
    by the sigma coefficient (which might also be considered to be a weight of uncertainty), then an alert is thrown.
    '''
    
    def __init__(self, rrd_query, ds_match, warn_coeff=2, crit_coeff=3, sample_time='now', count=-5, interval=604800, window=1800,debug=0):
        '''
        __init__ just stores a reference to the rrd_query structure and all of the arguments needed.
        Arguments are described further below in the ArgumentParser definition.
        '''
        
        self.rrd_query      = rrd_query
        self.ds_match       = ds_match
        self.warn_coeff     = warn_coeff
        self.crit_coeff     = crit_coeff
        self.sample_time    = sample_time
        self.count          = count
        self.interval       = interval
        self.window         = window
        self.debug          = debug
        
    
    def probe(self):
        '''
        probe builds the rrd query, calls the query, parses the output and generates metrics
        
        Unfortunately, I wasn't able to get the python rrd module working for whatever reason
        so I built my own rrd_query mechanism. It's ugly but gets the job done.
        '''
        
        for metric in self.rrd_query.get_metric_labels():
        
            # Define rrd dataset for the metric
            ds = self.rrd_query.define_dataset(metric)
        
            # Define the prediction rrd stuff  (self, cdef, step=604800, step_count=-5, window=1800):
            predict_tokens = self.rrd_query.define_prediction(cdef=ds,
                                                              step=self.interval,
                                                              step_count=self.count,
                                                              window=self.window,
                                                              )
            
            # Define an moving window average to smooth out the current rate.
            # It is this average that we will compare to the predicted. That way there will be less chance
            # of a false positive caused by a sudden drop/glitch
            # We'll use rrd TRENDNAN for this purpose
            
            rdef_str = '{},{},TRENDNAN'.format(ds, (self.window)/2)
            ds_smooth = '{}_smooth'.format(ds)
            self.rrd_query.define_cdef(ds_smooth, rdef_str)
            
            # Add this to the working tokens
            predict_tokens.append(ds_smooth)
            #predict_tokens.append(ds)
            
            # Create a current vdef and print statement for each cdef defined by the prediction definition
            # and the smoothed average
            # Build a regexp dict to help parse the rrd output when it is done.
            vdef_tokens = []
            
            for token in predict_tokens:
                vdef_name       = 'curr_{}'.format(token)
                rdef_str        = '{},LAST'.format(token)
                vdef_tokens.append(self.rrd_query.define_vdef(vdef_name, rdef_str))
            
            if(self.debug):
                for line in vdef_tokens:
                    sys.stderr.write('{}\n'.format(line))
            
            for token in vdef_tokens:
                self.rrd_query.define_print(token)
                       
        # Run the query
        rrd_output = self.rrd_query.run_query()
        
        if(self.debug):
            for line in rrd_output:
                sys.stderr.write('{}\n'.format(line))
        
        rrd_output_map = {}
        
        # Parse the output and map it to metrics
        output_parser = re.compile(r'^curr_ds(.*) = (.*)')
        for line in rrd_output:
            match = output_parser.match(line)
            if match:
                rrd_output_map[match.group(1)] = float(match.group(2))
        
#                if 'pred' in match.group(1):
#                    predicted = float(split_line[1])
#                else:
#                    if 'sigma' in match.group(1):
#                        sigma = float(split_line[1])
#            else:
#                measured = float(split_line[1])

#            # Figure out the difference
#            difference = abs(measured - predicted)

#        return_list = []
        submetric_list = ["_smooth", "_pred", "_sigma"]
        for metric in self.rrd_query.get_metric_labels():
            for submetric in submetric_list:
                yield nagiosplugin.Metric(metric + submetric, rrd_output_map[metric + submetric])
            
            # calculate difference
            difference = abs(rrd_output_map[metric] - rrd_output_map[metric + "_pred"])
            yield nagiosplugin.Metric(metric + "_diff", difference)
        
@nagiosplugin.guarded
def main():
    # Come up with a decent default perfdata path that accounts for OMD
    perfdata_path = "{}/var/pnp4nagios/perfdata".format(os.environ.get('OMD_ROOT', ''))
    # Setup argparse to parse the command line.
    cmdParser = argparse.ArgumentParser(description='check_predicted.py options')
    cmdParser.add_argument('-H ', '--host', dest='host', action='store',
                           help='invID to query')
    cmdParser.add_argument('--path', dest='path', action='store',
                           default=perfdata_path,
                           help='Path to perfdata directory')
    cmdParser.add_argument('--servicename', dest='service_name', action='store',
                           default='Interface_1', help='service to query')
    cmdParser.add_argument('--dsname', dest='ds_name', action='store',
                           default='out', help='specific service metric to query')
    cmdParser.add_argument('-w', '--warn', dest='warn_coeff', action='store',
                           default=1, help='sigma coefficient variation before warn - higher is less sensitive')
    cmdParser.add_argument('-c', '--crit', dest='crit_coeff', action='store',
                           default=2, help='sigma coefficient variation before crit - higher is less sensitive')
    cmdParser.add_argument('--timeout', dest='timeout', action='store', type=int,
                           default=40, help='Timeout value')
    cmdParser.add_argument('--sampletime', dest='sample_time', action='store',
                           default='now', help='Sets a specific sample time. Use rrd time format')
    cmdParser.add_argument('--samplecount', dest='sample_count', action='store', type=int,
                           default=-5, help='Number of back samples to take (Should be negative)')
    cmdParser.add_argument('--sampleinterval', dest='sample_interval', action='store', type=int,
                           default=604800, help='Interval between samples (In seconds)')
    cmdParser.add_argument('--samplewindow', dest='sample_window', action='store', type=int,
                           default=1800, help='Size of sample window (In seconds)')
    cmdParser.add_argument('--debug', dest='debug', action='store', type=int, choices=xrange(0, 2),
                           default=0, help='Debug verbosity level')
    args = cmdParser.parse_args()
    
    # Initialize the rrd query
    # I know start_time is a kludge. Will fix.
    predict_query = rrd_query.RRDQuery(invID=args.host,
                                       perfdata_path=args.path,
                                       service_name=args.service_name,
                                       out_file='/tmp/{}'.format(args.host),
                                       start_time='end-6w',
                                       end_time=args.sample_time, debug=args.debug)
    
    # Initialize the nagios plugin Check object
    check = nagiosplugin.Check(MetricPredict(predict_query,
                                              ds_match=args.ds_name,
                                              warn_coeff=args.warn_coeff,
                                              crit_coeff=args.crit_coeff,
                                              sample_time=args.sample_time,
                                              count=args.sample_count,
                                              interval=args.sample_interval,
                                              window=args.sample_window,
                                              debug=args.debug),
                               nagiosplugin.ScalarContext('difference', '0', ':',
                                                          fmt_metric='Measured value is {value} below predicted - sigma'),
                               nagiosplugin.ScalarContext('measured', None, None,
                                                          fmt_metric='{value} measured bps'),
                               nagiosplugin.ScalarContext('predicted', None, None,
                                                          fmt_metric='{value} predicted bps'),
                               nagiosplugin.ScalarContext('sigma', None, None,
                                                          fmt_metric='{value} sigma uncertainty')
                              )
    check.main(args.debug, args.timeout)
    
if __name__ == '__main__':
    main()
        

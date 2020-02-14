#!/usr/bin/env python

# check_predicted.py
# version 0.6.1
# check_predicted.py uses rrdtool's prediction functions to detect unusual behavior.
# It was originally to be used for interface traffic, but hopefully it will find use in other data sets.
# Originally written by Patrick Gavin. March 2013
# Retooled for OMD/check-mk Feb 2020
#
# check_predicted utilizes the nagiosplugin class and also assumes an OMD environment.
# The --path argument can be used to point to a different rrd file location if necessary.
#
# Right now I have the check running in my OMD/check_mk environment. It will trigger on anomalies depending
# on how you set the warn and crit options. A setting of 1 means that it will alert if the difference between predicted
# and actual exceeds the standard deviation. The higher the value, the less sensitive it is.


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
import xml.etree.ElementTree as ET

def load_XML(xml_path):
    '''
    load_XML loads the service XML file and returns the root node of the tree.
    '''

    tree = ET.parse(xml_path)
    return tree.getroot()

class MetricPredict(nagiosplugin.Resource):
    '''
    class MetricPredict looks at performance data rrds, makes a prediction on what the specified metric should
    be and then compares it to the current measurement of that metric.
    
    If the current measurement differs from the prediction by more than the standard deviation (sigma) multiplied
    by the sigma coefficient (which might also be considered to be a weight of uncertainty), then an alert is thrown.
    
    The default settings for MetricPredict are pretty good. 5 sample windows of 30 minutes with a week inbetween.
    '''
    
    def __init__(self, rrd_query, invID, perfdata_path, service_name, ds_match, sample_time='now', count=-5, interval=604800, window=1800,debug=0):
        '''
        __init__ just stores a reference to the rrd_query structure and all of the arguments needed.
        Arguments are described further below in the ArgumentParser definition.
        '''
        
        self.rrd_query      = rrd_query
        self.ds_match       = ds_match
        self.sample_time    = sample_time
        self.count          = count
        self.interval       = interval
        self.window         = window
        self.debug          = debug
        self.submetric_list = ["avg_smooth", "avg_pred", "avg_sigma", "avg_diff"]
        self.service_meta   = load_XML('{}/{}/{}.xml'.format(perfdata_path, invID, service_name))
        self.label_dict     = self.build_label_dict()
    
    
    def build_label_dict(self):
        '''
        buildDict will create a dict that maps the datastore value to the name or label
        using the xml file that pnp4nagios automatically creates. It now also extracts the
        rrdfile as well, since check_mk likes to break up metrics into seperate files.
        '''

        # Initialize the dictionary that will be returned
        return_dict = {}

        for datasource in self.service_meta.findall('DATASOURCE'):
            ds_num = datasource.find('DS').text
            name = datasource.find('NAME').text
            path = datasource.find('RRDFILE').text
            return_dict[name] = (path, ds_num)

        return return_dict
        
    
    def probe(self):
        '''
        probe builds the rrd query, calls the query, parses the output and generates metrics
        
        Unfortunately, I wasn't able to get the python rrd module working for whatever reason
        so I built my own rrd_query mechanism. It's ugly but gets the job done.
        '''
        
        for metric in self.label_dict.keys():
            # I know there's a better way to do this.
            (path, ds_num) = self.label_dict[metric]
            
            # Define rrd dataset for the metric
            ds = self.rrd_query.define_dataset(path, ds_num, metric_name=metric)
        
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
            
            # Calculate difference in rrd as well
            # NOTE! The difference is this case is abs(predicted - observed) / std_deviation
            # This way the figure can be compared directly to the warning and critical levels
            # If sigma is 0, then the difference will be NaN, so we have to filter those out.
            # Psuedocode for the RPN in rdef_str is:
            # if(sigma == 0):
            #     return 0
            # else:
            #     return abs(observed - predicted)/sigma
            
            rdef_str = '{2},0,EQ,0,{0},{1},-,ABS,{2},/,IF'.format(ds_smooth, ds + '_pred', ds + '_sigma')
            ds_diff = '{}_diff'.format(ds)
            self.rrd_query.define_cdef(ds_diff, rdef_str)
            
            # Add this to the working tokens
            predict_tokens.append(ds_diff)
            
            # Create a current vdef and print statement for each cdef defined by the prediction definition
            # and the smoothed average (and any difference or sigma coeff calculations)
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
        
        # Parse the output and map it to metrics
        rrd_output_map = {}
        output_parser = re.compile(r'^curr_ds(.*) = (.*)')
        for line in rrd_output:
            match = output_parser.match(line)
            if match:
                rrd_output_map[match.group(1)] = float(match.group(2))
        
        if(self.debug):
            for metric in rrd_output_map.keys():
                sys.stderr.write('{} = {}\n'.format(metric, rrd_output_map[metric]))

        # Generate the output metrics
        # Generally we just output the diffs, but if debug is on we output all metrics
        for metric in self.label_dict.keys():
            for submetric in self.submetric_list:
                if(re.search('_diff$', submetric)):
                    yield nagiosplugin.Metric(metric + submetric, rrd_output_map[metric + submetric])
                else:
                    if(self.debug):
                        yield nagiosplugin.Metric(metric + submetric, rrd_output_map[metric + submetric])

class PredictSummary(nagiosplugin.Summary):
    '''
    PredictSummary class provides a summary string for the plugin output
    '''
    def __init__(self):
        pass

    def ok(self, results):
        return 'All metrics are within expected range'

#    def problem(self, results):

@nagiosplugin.guarded
def main():
    # Come up with a decent default perfdata path that accounts for OMD
    if os.environ.get('OMD_ROOT', ''):
       perfdata_path = "{}/var/pnp4nagios/perfdata".format(os.environ.get('OMD_ROOT', ''))
    else:
       perfdata_path = "/usr/local/pnp4nagios/perfdata"
    # Setup argparse to parse the command line.
    cmdParser = argparse.ArgumentParser(description='check_predicted.py options')
    cmdParser.add_argument('-H ', '--host', dest='host', action='store',
                           help='hostname to query')
    cmdParser.add_argument('--path', dest='path', action='store',
                           default=perfdata_path,
                           help='Path to perfdata directory')
    cmdParser.add_argument('--servicename', dest='service_name', action='store',
                           default='Interface_1', help='service to query')
    cmdParser.add_argument('--sm', dest='ds_name', action='store',
                           default='out', help='specific submetric to query')
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

#invID=args.host,
#    perfdata_path=args.path,
#        service_name=args.service_name,
#

    predict_query = rrd_query.RRDQuery(out_file='/tmp/{}'.format(args.host),
                                       start_time='end-6w',
                                       end_time=args.sample_time,
                                       debug=args.debug)
    
    # Initialize the resource
    predict_resource = MetricPredict(predict_query,
                                     invID=args.host,
                                     perfdata_path=args.path,
                                     service_name=args.service_name,
                                     ds_match=args.ds_name,
                                     sample_time=args.sample_time,
                                     count=args.sample_count,
                                     interval=args.sample_interval,
                                     window=args.sample_window,
                                     debug=args.debug)
    
    # Initialize the nagios plugin Check object
    check = nagiosplugin.Check(predict_resource, PredictSummary())

    # Add contexts to the Check object
    for metric in predict_resource.label_dict.keys():
        for submetric in predict_resource.submetric_list:
            if(re.search('_diff$', submetric)):
                check.add(nagiosplugin.ScalarContext(metric + submetric, args.warn_coeff, args.crit_coeff))
            else:
                if(args.debug):
                    check.add(nagiosplugin.ScalarContext(metric + submetric, None, None))


    check.main(args.debug, args.timeout)
    
if __name__ == '__main__':
    main()
        

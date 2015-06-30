"use strict";

// debugging
var debug = false;

function log(o) {
    if (debug) {
        console.log(o);
    }
}

// find visible width/height 
var w = window,
    d = document,
    e = d.documentElement,
    g = d.getElementsByTagName('body')[0];

var total_width = w.innerWidth || e.clientWidth || g.clientWidth;
var total_height = w.innerHeight || e.clientHeight || g.clientHeight;

// set chart dimensions
var dimensions = {
    page: {
        left: 20,
        top: 30
    },
    height: {
        per_chart: 0,
        overview: 80,
        x_axis: 20,
        above_charts: 5,
        below_charts: 30,
        tooltip: 15,
        bar_factor_unselected: .12,
        bar_factor_selected: .15,
        split_factor: .60
    },
    width: {
        chart: 0,
        y_axis: 60,
        sidebar: 180,
    },
}

// metric lists
var availableMetrics = [
    "ta",
    "ra",
    "typestr",
    "seq",
    "rate",
    "orig_len",
    "pcap_secs",
    "mac_usecs",
    "streamId",
    "antenna",
    "dbm_antnoise",
    "dbm_antsignal",
    "dsmode",
    "duration",
    "powerman",
    "retry",
    "mcs"
];

var selectableMetrics = [
    "seq",
    "mcs",
    "spatialstreams",
    "bw",
    "rate",
    "retry",
    "type",
    "typestr",
    "dsmode",
    "dbm_antsignal",
    "dbm_antnoise",
    "bad"
];

// settings per selectable metric
var field_settings = {
    'pcap_secs': {
        'value_type': 'number',
        'scale_type': 'linear',
        'height_factor': 1
    },
    'seq': {
        'value_type': 'number',
        'scale_type': 'linear',
        'height_factor': 1
    },
    'rate': {
        'value_type': 'number',
        'scale_type': 'linear',
        'height_factor': 1
    },
    'retry-bad': {
        'value_type': 'retrybad',
        'scale_type': 'linear',
        'height_factor': .55
    },
    'retry': {
        'value_type': 'boolean',
        'scale_type': 'linear',
        'height_factor': .4
    },
    'bad': {
        'value_type': 'boolean',
        'scale_type': 'linear',
        'height_factor': .6
    },
    'bw': {
        'value_type': 'boolean',
        'scale_type': 'linear',
        'height_factor': .4
    },
    // note - spatial streams is actually values of 1 and 2, rather than 0 and 1 - this works, but is a hack
    'spatialstreams': {
        'value_type': 'boolean',
        'scale_type': 'linear',
        'height_factor': .4
    }
}

// complete selectable metrics 
for (var i in selectableMetrics) {
    if (!field_settings[selectableMetrics[i]]) {
        field_settings[selectableMetrics[i]] = {
            'value_type': 'number',
            'scale_type': 'linear',
            'height_factor': 1
        }
    }
}

// GLOBAL VARIABLES 

// state
var state = {
    to_plot: [],
    scales: [],
    // When not null, crosshairs will focus only on packets for this stream.
    selected_data: {
        stream: null,
        access: null,
        station: null,
        //   direction: null,
    }
}

var reticle = {}; // dict[field; crosshair]
var histogramPacketNum = [] // array to be used to create overview histogram
var number_of_packets;

var dataset; // all packets, sorted by pcap_secs
var stream2packetsDict = {}; // look up values and direction by streamId
var stream2packetsArray = []; // array of stream ids
var addresses = {} // look up direction and alias name by mac address

var zoom_duration = 750; // how long does transition on zoom take
var zoom_stack = []; // keep track of past zoom domain (pcap secs)

// x (pcap) axis for all charts
var pcapSecsAxis = d3.svg.axis()
    .tickFormat(hourMinuteMilliseconds)
    .orient('bottom')
    .ticks(5);

// brush object for zooming using top level histogram chart
var brush = d3.svg.brush()
    .on("brushend", function() {
        zoom_stack = [brush.empty() ? state.scales['pcap_secs_fixed'].domain() : brush.extent()];
        update_pcaps_domain(zoom_stack[0], false);
    });

// binary search function for pcap_secs
var binary_search_by_pcap_secs =
    d3.bisector(function(d) {
        return d.pcap_secs
    }).left

// helper function for scales
function scaled(name) {
    return function(d) {
        return state.scales[name](d[name]);
    }
}

// get data & visualize [main function!]
d3.json('/json/' + decodeURIComponent(get_query_param('key')[0]), function(error, json) {
    if (error) return console.error('error', error);

    // update title
    document.getElementById("title").innerHTML = json.filename;

    // set up 
    init(json);

    // visualize
    draw();
})

function init(json) {
    // TODO(katepek): Should sanitize here? E.g., discard bad packets?
    // Packets w/o seq?
    console.log(json)
    dataset = json.js_packets;

    state.to_plot = get_query_param('to_plot');

    // Leave only packets that have all the fields that we want to plot
    sanitize_dataset();

    dataset.sort(function(x, y) {
        return x['pcap_secs'] - y['pcap_secs'];
    });

    // TODO(katepek): Recalculate and redraw when resized
    dimensions.height.per_chart = Math.max((total_height - dimensions.height.overview - dimensions.page.top - (state.to_plot.length + 1) * (dimensions.height.above_charts + dimensions.height.below_charts + dimensions.height.x_axis)) / state.to_plot.length, 100);
    dimensions.width.chart = total_width - dimensions.page.left - dimensions.width.y_axis - dimensions.width.sidebar;

    var x_range = [0, dimensions.width.chart];
    var y_range = [dimensions.height.per_chart, 0];

    log('total_height = ' + total_height);
    log('height = ' + dimensions.height.per_chart);

    add_scale('pcap_secs', x_range);
    state.to_plot.forEach(function(d) {
        add_scale(d, y_range)
    });
    // add scale for legend, based on pcap_secs scale
    state.scales['pcap_secs_fixed'] = d3.scale.linear().domain(state.scales['pcap_secs'].domain()).range(state.scales['pcap_secs'].range());

    pcapSecsAxis.scale(state.scales['pcap_secs']);

    // get array of all packetSecs and use a histogram
    var packetSecs = []

    for (var a in json.aliases) {
        addresses[a.replace(/:/gi, "")] = {
            "name": json.aliases[a]
        }
    }

    addresses['badpacket'] = {
        "name": "bad_packet"
    }

    dataset.forEach(function(d) {
        if (d.bad == 1) {
            d.ta = 'badpacket';
            d.ra = 'badpacket';
        }
        // store time of packet
        packetSecs.push(d.pcap_secs)

        // track streams
        var streamId = to_stream_key(d);
        d.ta = d.ta.replace(/:/gi, "")
        d.ra = d.ra.replace(/:/gi, "")

        // Should I check if type already exists?  Or just assign?  Which is faster?
        // Logic: if dsmode = 2, then assign as downstream. If dsmode == 1, then assign as upstream. If dsmode 
        if (d.dsmode == 2) {
            addresses[d.ta].type = "access";
            addresses[d.ra].type = "station"
        } else if (d.dsmode == 1) {
            addresses[d.ra].type = "access";
            addresses[d.ta].type = "station"
        } else if (d.dsmode == 0) {
            if (addresses[d.ta].type == 'access') {
                addresses[d.ra].type = "station"
            } else if (addresses[d.ta].type == 'station') {
                addresses[d.ra].type = "access"
            } else if (addresses[d.ra].type == 'access') {
                addresses[d.ta].type = "station"
            } else if (addresses[d.ra].type == 'station') {
                addresses[d.ta].type = "access"
            }
        }

        d.streamId = streamId;
        if (!stream2packetsDict[streamId]) {
            stream2packetsDict[streamId] = {
                values: [d]
            };
            stream2packetsArray.push(streamId);
        } else {
            stream2packetsDict[streamId].values.push(d);
        }
    })

    stream2packetsArray.forEach(function(stream) {
        var k = to_ta_ra_from_stream_key(stream);
        if (addresses[k[0]].type == 'access' || addresses[k[1]].type == 'station') {
            stream2packetsDict[stream].direction = 'downstream';
        } else if (addresses[k[1]].type == 'access' || addresses[k[0]].type == 'station') {
            stream2packetsDict[stream].direction = 'upstream';
        } else {
            console.log(stream, 'direction not found')
        }
    })

    // set up histogram with 1000 bins
    number_of_packets = packetSecs.length;
    histogramPacketNum = d3.layout.histogram().bins(1000)(packetSecs);

    // construct array to keep track of bin edges relative to dataset slices to aid in adding/removing points
    var dataSliceTracker = [];
    var count = 0;
    histogramPacketNum.forEach(function(d, i) {
        dataSliceTracker.push(count)
        count = count + d.y;
    })

    // sort streams by number of packets per stream
    stream2packetsArray.sort(function(a, b) {
        return stream2packetsDict[b].values.length - stream2packetsDict[a].values.length
    })
}

// helper functions for init
function get_query_param(param) {
    var urlKeyValuePairs = {}
    window.location.href.split("#")[1].split("&").forEach(function(d) {
        var m = d.split("=");
        urlKeyValuePairs[m[0]] = m[1]
    })
    return urlKeyValuePairs[param].split(',')
}

function to_stream_key(d) {
    return d['ta'].replace(/:/g, '') + '---' + d['ra'].replace(/:/g, '');
}

function to_visible_stream_key(streamId) {
    var z = streamId.match(/(([a-z]|[A-Z]|[0-9])+)---(([a-z]|[A-Z]|[0-9])+)/)
    return addresses[z[1]].name + '→' + addresses[z[3]].name;
}

function to_ta_ra_from_stream_key(streamId) {
    var z = streamId.match(/(([a-z]|[A-Z]|[0-9])+)---(([a-z]|[A-Z]|[0-9])+)/)
    return [z[1], z[3]];
}

function complement_stream_id(key) {
    // match any letter/number for aliases
    var re = /(([a-z]|[A-Z]|[0-9])+)---(([a-z]|[A-Z]|[0-9])+)/
    var z = key.match(re)
    return z[3] + "---" + z[1]
}

// helper functions for init
function get_query_param(param) {
    var urlKeyValuePairs = {}
    window.location.href.split("#")[1].split("&").forEach(function(d) {
        var m = d.split("=");
        urlKeyValuePairs[m[0]] = m[1]
    })
    return urlKeyValuePairs[param].split(',')
}

var excludedData = {
    'no_pcap_value': {
        count: 0
    },
    'non_positive_pcap_value': {
        count: 0
    },
    'type_ack': {
        count: 0
    },
    'null_ta': {
        count: 0
    },
    'null_ra': {
        count: 0
    },
    'missing_plottype': {
        count: 0
    }
}

function sanitize_dataset() {
    var before = dataset.length;
    log('Before filtering: ' + dataset.length);
    dataset = dataset.filter(function(d) {
        if (!d['pcap_secs']) {
            excludedData.no_pcap_value.count++;
        }
        if (d['pcap_secs'] <= 0) {
            excludedData.non_positive_pcap_value.count++;
        }

        // exclude ACK
        if (d['typestr'] == '1D ACK') {
            excludedData.type_ack.count++;
            return false;
        }

        // exclude null ta (remove this?)
        if (!d['ta']) {
            excludedData.null_ta.count++;
            return false;
        }

        for (var idx in state.to_plot) {
            if (!d.hasOwnProperty(state.to_plot[idx])) {
                excludedData.missing_plottype.count++;
            }
        }
        return true;
    });
    log(excludedData)
    log("Percent of packets removed: ", (before - dataset.length) / before)
    log('After filtering: ' + dataset.length);
}

function add_scale(field, range) {
    state.scales[field] = d3.scale[field_settings[field]['scale_type']]()
        .domain([d3.min(dataset, function(d) {
                return d[field]
            }),
            d3.max(dataset, function(d) {
                return d[field]
            })
        ])
        .range(range);

    if (!(state.scales[field].domain()[0]) || !(state.scales[field].domain()[0])) {
        log(field, 'is missing')
    }
}

function draw() {
    add_butter_bar();

    add_overview();

    state.to_plot.forEach(function(d) {
        visualize(d)
    })

    add_legend();
}

function add_overview() {
    var max = 0;

    // find max bar height and use to set Y axis for overview chart
    histogramPacketNum.forEach(function(d) {
        if (d.y > max) {
            max = d.y;
        }
    })
    state.scales["packetNumPerTenth"] = d3.scale.linear().domain([0, max]).range([dimensions.height.overview, 0])

    // set up axis
    var overviewYaxis = d3.svg.axis()
        .scale(state.scales['packetNumPerTenth'])
        .orient('right')
        .ticks(3);

    var overviewXaxis = d3.svg.axis()
        .scale(state.scales['pcap_secs_fixed'])
        .tickFormat(hourMinuteMilliseconds)
        .orient('bottom')
        .ticks(5);

    // start building the chart
    var overviewChart = d3
        .select('body')
        .append('svg')
        .attr('id', 'histogramZoomNav')
        .attr('class', 'overviewChart')
        .attr('width', dimensions.width.chart + dimensions.width.y_axis)
        .attr('height', dimensions.height.overview + dimensions.height.x_axis + dimensions.height.above_charts + dimensions.height.below_charts)
        .append("g")
        .attr("transform", "translate(" + dimensions.page.left + ",0)");

    // append x-axis
    overviewChart.append('g')
        .attr('class', 'axis x overview')
        .attr('transform', 'translate(0,' + dimensions.height.overview + ')')
        .call(overviewXaxis);

    overviewChart.append('g')
        .attr('class', 'axis y overview')
        .attr('transform', 'translate(' + dimensions.width.chart + ', 0)')
        .call(overviewYaxis);

    // draw bars
    overviewChart.selectAll(".histBar")
        .data(histogramPacketNum)
        .enter().append("rect")
        .attr("class", "histBar")
        .attr("x", function(d) {
            return state.scales['pcap_secs_fixed'](d.x)
        })
        .attr("y", function(d) {
            return state.scales["packetNumPerTenth"](d.y);
        })
        .attr("width", function(d) {
            return state.scales['pcap_secs_fixed'](d.x + d.dx) - state.scales['pcap_secs_fixed'](d.x)
        })
        .attr("height", function(d) {
            return dimensions.height.overview - state.scales["packetNumPerTenth"](d.y)
        });

    // set initial x value for brush
    brush.x(state.scales['pcap_secs_fixed'])

    // append brush
    overviewChart.append("g")
        .attr("class", "x brush")
        .call(brush)
        .selectAll("rect")
        .attr("y", -6)
        .attr("height", dimensions.height.overview + 7);
}

function add_butter_bar() {
    var butter_bar_height = 30;
    var svg = d3
        .select('body')
        .append('svg')
        .attr('id', 'butter_bar')
        .attr('width', dimensions.width.chart)
        .attr('height', butter_bar_height);
    svg.append('rect')
        .attr('id', 'butter_bar_box')
        .attr('width', dimensions.width.chart)
        .attr('height', butter_bar_height)
        .style('fill', 'none');
    svg.append('text')
        .attr('id', 'butter_bar_msg')
        .attr('class', 'legend')
        .attr('x', dimensions.width.chart / 2)
        .attr('y', butter_bar_height / 2 + 5)
        .style('fill', 'black')
        .style('font-size', 14);
}

function add_legend() {
    var font_width = 6;
    var key_length = font_width * 40;
    var n_cols = Math.floor(dimensions.width.chart / key_length);
    var n_rows = Math.ceil(stream2packetsArray.length / n_cols)
    var legend_line_height = 24;

    d3.select('body')
        .append('svg')
        .attr('width', dimensions.width.chart)
        .attr('height', n_rows * 12)
        .attr('class', 'legendG')
        .append("g")
        .attr("transform", "translate(" + dimensions.page.left + ",0)")
        .selectAll(".legend")
        .data(stream2packetsArray)
        .enter()
        .append('text')
        .attr('class', function(d) {
            return 'legend stream_' + d +
                ' ta_' + d.split("---")[0] +
                ' ra_' + d.split("---")[1] +
                ' direction' + stream2packetsDict[d].direction;
        })
        .attr('x', function(d, i) {
            return (i % n_cols) * key_length
        })
        .attr('y', function(d, i) {
            return (Math.floor(i / n_cols) + .5) * legend_line_height

        })
        .text(function(d) {
            return to_visible_stream_key(d)
        })
        .on('click', function(d) {
            var direction = "downstream";
            var ta = d.split("---")[0];
            var ra = d.split("---")[1];
            if (addresses[ta].type == 'station' || addresses[ra].type == 'access') {
                direction = "upstream";
            }
            highlight_stream({
                'streamId': d,
                'ta': ta,
                'ra': ra,
                'direction': direction,
            })
        });
}

function butter_bar(text) {
    d3.select('text#butter_bar_msg')
        .style('opacity', 1)
        .text(text);
    d3.select('rect#butter_bar_box')
        .style('opacity', 1)
        .style('fill', 'red');
    d3.select('text#butter_bar_msg')
        .transition()
        .duration(2000)
        .style('opacity', 0);
    d3.select('rect#butter_bar_box')
        .transition()
        .duration(700)
        .style('opacity', 0);
}

d3.select('#tooltip')
    .style('top', dimensions.page.top + 'px')
    .classed('hidden', true)
    .append("svg")
    .attr("width", dimensions.width.sidebar - 10)
    .attr("height", availableMetrics.length * dimensions.height.tooltip)
    .selectAll('.tooltipValues')
    .data(availableMetrics)
    .enter()
    .append("text")
    .attr("class", "tooltipValues")
    .attr("y", function(k, i) {
        return i * dimensions.height.tooltip + 10
    });

function visualize(field) {
    log('About to visualize ' + field);

    // set up main svg for plot
    var mainChart = d3.select('body')
        .append('svg')
        .attr('class', 'plot_' + field)
        .attr('width', dimensions.width.chart + dimensions.width.y_axis)
        .attr('height', field_settings[field].height_factor * dimensions.height.per_chart + dimensions.height.x_axis + dimensions.height.above_charts + dimensions.height.below_charts)
        .append("g")
        .attr("transform", "translate(" + dimensions.page.left + "," + dimensions.height.above_charts + ")");;

    if (field_settings[field].value_type == 'number') {
        visualize_numbers(field, mainChart)
    } else if (field_settings[field].value_type == 'boolean') {
        visualize_boolean(field, mainChart);
    } else if (field_settings[field].value_type == 'retrybad') {
        visualize_retrybad(mainChart);
    }

}

// helper functions for draw
function boolean_percent_of_total_area_setup(data, currentField, xFunc) {
    // percent 1 vs 0
    var runningSeq = [];
    var runningCount = 0;
    var rollingAverageLength = 20
    var k = d3.svg.area()
        .x(xFunc)
        .y0(function(d) {
            return dimensions.height.per_chart * dimensions.height.split_factor
        })
        .y1(function(d) {
            if (runningSeq.length > rollingAverageLength) {
                runningCount = runningCount - runningSeq.shift();
            }
            runningSeq.push(d[currentField]);
            runningCount = runningCount + d[currentField];
            return dimensions.height.per_chart * (1 - dimensions.height.split_factor) *
                (runningCount / rollingAverageLength) + dimensions.height.per_chart * dimensions.height.split_factor;
        })
        .interpolate("basis");

    return k(data)
}

function visualize_boolean(field, svg) {
    setup_crosshairs(field, svg)

    var boolean_boxes = svg.append('g').attr("class", 'boolean_boxes_' + field).attr("fill", "grey")

    // rectangle view 
    enter_boolean_boxes_by_dataset(field,
        boolean_boxes.selectAll('.bool_boxes_rect_' + field)
        .data(dataset, function(d) {
            return d.pcap_secs
        }));

    // uncomment this to show area chart
    //draw_boolean_percent_chart(field, svg);

    // x and y axis
    draw_metric_x_axis(svg, field);

    // Add crosshairs
    draw_vertical(reticle[field], field);

    // rect for zooming
    draw_rect_for_zooming(svg, dimensions.height.per_chart * field_settings[field].height_factor)
}

function setup_crosshairs(field, svg) {
    // set up crosshairs element
    reticle[field] = svg.append('g')
        .attr("class", "focus")
        .style('display', null);
}

function visualize_retrybad(svg) {
    setup_crosshairs('retry-bad', svg)

    var boolean_boxes = svg.append('g').attr("class", 'boolean_boxes_retry-bad').attr("fill", "grey")

    // box charts
    enter_retrybad_boxes_by_dataset(
        boolean_boxes.selectAll('.bool_boxes_rect_retry-bad')
        .data(dataset, function(d) {
            return d.pcap_secs
        }));

    // To include dripping percent chart, uncomment the line below
    // draw_retrybad_percent_chart(svg);

    // x axis
    draw_metric_x_axis(svg, 'retry-bad');


    // Add crosshairs
    draw_vertical(reticle['retry-bad'], 'retry-bad');

    // zooming object
    draw_rect_for_zooming(svg, dimensions.height.per_chart * field_settings['retry-bad'].height_factor)
}

function draw_boolean_percent_chart(field, svg) {

    svg.append("path")
        .attr("class", "percent_area_chart_boolean_" + field)
        .attr("d", boolean_percent_of_total_area_setup(dataset, field, scaled('pcap_secs')));
}

// function to transform stack data into area charts
var retrybad_percent_area = d3.svg.area()
    .x(function(d) {
        return state.scales['pcap_secs'](d.x);;
    })
    .y0(function(d) {
        return dimensions.height.per_chart * (1 - dimensions.height.split_factor) * d.y0 +
            dimensions.height.per_chart * dimensions.height.split_factor;
    })
    .y1(function(d) {
        return dimensions.height.per_chart * (1 - dimensions.height.split_factor) * (d.y + d.y0) +
            dimensions.height.per_chart * dimensions.height.split_factor;
    });

function draw_retrybad_percent_chart(svg) {
    // set up data for rolling average
    var runningSeq = {
        "retry": [],
        "bad": [],
        "both": []
    };
    var runningCount = {
        "retry": 0,
        "bad": 0,
        "both": 0
    };
    var rollingAverageLength = 16

    // keep track of seconds, for centering the window
    var secondsCounter = []

    var types = ["bad", "retry"]

    // calculate the moving averages
    var movingAveData = types.map(function(type) {
        return dataset.map(function(d) {
            var value = d[type];

            if (type == "retry" & d.bad == 1) {
                // this means that if bad and retry are both 1, then we only count it for bad
                value = 0;
            }

            secondsCounter.push(d.pcap_secs)

            // keep running count and sequence
            if (runningSeq[type].length >= rollingAverageLength) {
                // drop the old value
                runningCount[type] = runningCount[type] - runningSeq[type].shift();
            }
            runningSeq[type].push(value);

            // add the new value
            runningCount[type] = runningCount[type] + value;

            // center the results
            if (secondsCounter.length > rollingAverageLength / 2) {
                return {
                    x: secondsCounter.shift(),
                    y: runningCount[type] / rollingAverageLength
                };
            } else {
                return {
                    x: d.pcap_secs,
                    y: 0
                }
            }

        });
    });

    // use D3 stack layout to set up the stack from the raw data
    var stack = d3.layout.stack()(movingAveData)

    // use the stack as the data input and call the area function to access
    svg.selectAll(".percent_area")
        .data(stack)
        .enter()
        .append("path")
        .attr("class", function(d, i) {
            return "percent_area" + " type_" + types[i]
        })
        .attr("d", function(d) {
            return retrybad_percent_area(d);
        });

}

function enter_boolean_boxes_by_dataset(fieldName, svg) {

    svg.enter()
        .append('rect')
        .attr('x', scaled('pcap_secs'))
        .attr('y', function(d) {
            if (fieldName != 'spatialstreams') {
                if (d[fieldName] == 1) {
                    return 0
                } else {
                    return dimensions.height.per_chart * .2
                }
            } else {
                if (d[fieldName] == 2) {
                    return 0
                } else {
                    return dimensions.height.per_chart * .2
                }
            }
        })
        .attr('width', 2)
        .attr('height', function(d) {
            if (determine_selected_class(d) == "" || determine_selected_class(d) == "badpacket") {
                return dimensions.height.per_chart * dimensions.height.bar_factor_unselected
            } else {
                return dimensions.height.per_chart * dimensions.height.bar_factor_selected
            }
        })
        .attr("class", function(d) {
            return 'bool_boxes bool_boxes_rect_' + fieldName + " " + ' ta_' + d.ta + ' ra_' + d.ra + ' stream_' + d.streamId + " " + determine_selected_class(d);
        })
        .on("click", function(d) {
            highlight_stream(d)
        })
        .on("mouseover", function(d) {
            d3.select('#tooltip').classed("hidden", false)
            update_crosshairs(d);
        })
        .on("mouseout", function(d) {
            d3.select('#tooltip').classed("hidden", true)
        })
}

function enter_retrybad_boxes_by_dataset(svg) {

    svg.enter()
        .append('rect')
        .attr('x', scaled('pcap_secs'))
        .attr('y', function(d) {
            // order is bad on top, then retry, the all: note that if it's bad AND retry, it counts only as bad
            if (d['bad'] == 1) {
                return 0
            } else if (d['retry'] == 1) {
                return dimensions.height.per_chart * .16
            } else {
                return dimensions.height.per_chart * .32
            }
        })
        .attr('width', 1)
        .attr('height', function(d) {
            // selected rectangles are taller/longer
            if (determine_selected_class(d) == "" || determine_selected_class(d) == "badpacket") {
                return dimensions.height.per_chart * dimensions.height.bar_factor_unselected
            } else {
                return dimensions.height.per_chart * dimensions.height.bar_factor_selected
            }
        })
        .attr("class", function(d) {
            return 'bool_boxes_rect_retry-bad' + " " + ' ta_' + d.ta + ' ra_' + d.ra + ' stream_' + d.streamId + " " + determine_selected_class(d);
        })
        .on("click", function(d) {
            highlight_stream(d)
        })
        .on("mouseover", function(d) {
            d3.select('#tooltip').classed("hidden", false)
            update_crosshairs(d);
        })
        .on("mouseout", function(d) {
            d3.select('#tooltip').classed("hidden", true)
        })
}

function determine_selected_class(d) {
    if (d.bad == 1) {
        return 'badpacket'
    } else if (!state.selected_data.stream || state.selected_data.stream == null) {
        return "";
    } else if (stream2packetsDict[stream].direction == "upstream") {
        if (state.selected_data.stream == d.streamId) {
            return 'selected_upstream';
        } else if (state.selected_data.access == d.ta && state.selected_data.station == d.ra) {
            return 'selected_downstream';
        } else if (state.selected_data.station == d.ta || state.selected_data.access == d.ra) {
            return 'selected_partialMatch_upstream';
        }
    } else {
        if (state.selected_data.stream == d.streamId) {
            return 'selected_downstream';
        } else if (state.selected_data.station == d.ra && state.selected_data.access == d.ta) {
            return 'selected_upstream';
        } else if (state.selected_data.access == d.ta || state.selected_data.station == d.ra) {
            return 'selected_partialMatch_downstream';
        } else {
            return "";
        }
    }

}


function visualize_numbers(field, svg) {
    setup_crosshairs(field, svg)

    // draw points
    draw_points(field, svg);

    // x and y axis
    draw_metric_x_axis(svg, field);
    draw_metric_y_axis(svg, field);

    // Add crosshairs
    draw_crosshairs(reticle[field]);

    // append the rectangle to capture mouse movements
    draw_rect_for_zooming(svg, dimensions.height.per_chart)
    draw_hidden_rect_for_mouseover(svg, field)
}

function draw_rect_for_zooming(svg, height) {
    svg.append("rect")
        .attr("height", height)
        .attr("width", 0)
        .attr("fill", "grey")
        .attr("opacity", .1)
        .attr("x", 0)
        .attr("y", 0)
        .attr("class", "drag_rect hidden")
}

function draw_points(fieldName, svg) {
    svg.append('g').attr("class", 'pcap_vs_' + fieldName + " metricChart").attr("fill", 'grey')
        .selectAll('.points')
        .data(dataset, function(d) {
            return d.pcap_secs
        })
        .enter()
        .append('circle')
        .attr('class', function(d) {
            return 'points' + ' ta_' + d.ta + ' ra_' + d.ra + ' stream_' + d.streamId + " " + determine_selected_class(d)
        })
        .attr('cx', scaled('pcap_secs'))
        .attr('cy', scaled(fieldName))
        .attr('r', 1.5);
}

function draw_metric_y_axis(svg, fieldName) {
    var yAxis = d3.svg.axis()
        .scale(state.scales[fieldName])
        .orient('right')
        .ticks(5);

    // y axis
    svg.append('g')
        .attr('class', 'axis y')
        .attr('transform', 'translate(' + (dimensions.width.chart) + ',0)')
        .call(yAxis);
}

function draw_metric_x_axis(svg, fieldName) {
    // title for plot
    svg.append("text")
        .attr('transform', 'translate(' + dimensions.width.chart / 2 + ',' + (field_settings[fieldName].height_factor * dimensions.height.per_chart + dimensions.height.x_axis + dimensions.height.below_charts / 3) + ')')
        .attr("class", "text-label")
        .attr("text-anchor", "middle")
        .text(fieldName);

    // x axis
    var xaxis = svg.append('g')
        .attr('class', 'axis x metric')
        .attr('transform', 'translate(0,' + (field_settings[fieldName].height_factor * dimensions.height.per_chart) + ')')

    xaxis.call(pcapSecsAxis);
    xaxis.append("rect").attr('height', dimensions.height.x_axis).attr('width', dimensions.width.chart).style('opacity', 0);

}

function update_pcaps_domain(newDomain, transition_bool) {
    // update charts
    state.scales['pcap_secs'].domain(newDomain);
    d3.selectAll(".axis.x.metric").call(pcapSecsAxis);

    // todo: better way of calling this more generally to update x-axis scale?
    var trimmed_data = trim_by_pcap_secs(dataset);

    state.to_plot.forEach(function(fieldName) {
        if (field_settings[fieldName].value_type == 'number') {
            var points = d3.selectAll('.pcap_vs_' + fieldName).selectAll('.points')
                .data(trimmed_data, function(d) {
                    return d.pcap_secs
                })

            points.exit().remove();

            if (transition_bool) {
                points.transition().duration(zoom_duration).attr('cx', scaled('pcap_secs'))
            } else {
                points.attr('cx', scaled('pcap_secs'))
            }
            points.enter()
                .append('circle')
                .attr('cy', scaled(fieldName))
                .attr("class", function(d) {
                    return 'points ' + ' ta_' + d.ta + ' ra_' + d.ra + ' stream_' + d.streamId + " " + determine_selected_class(d);
                }).attr('r', 2)
                .attr('cx', scaled('pcap_secs'));

        }

        if (field_settings[fieldName].value_type == 'boolean') {
            d3.selectAll(".percent_area_chart_boolean_" + fieldName)
                .attr("d", boolean_percent_of_total_area_setup(trimmed_data, fieldName, scaled('pcap_secs')));

            var bool_boxes_current = d3.select(".boolean_boxes_" + fieldName)
                .selectAll(".bool_boxes_rect_" + fieldName)
                .data(trimmed_data, function(d) {
                    return d.pcap_secs
                })
                // exit 
            bool_boxes_current.exit().remove()

            // update
            if (transition_bool) {
                bool_boxes_current.transition().duration(zoom_duration).attr('x', scaled('pcap_secs'));
            } else {
                bool_boxes_current.attr('x', scaled('pcap_secs'));
            }

            // enter
            enter_boolean_boxes_by_dataset(fieldName, bool_boxes_current)

        }

        if (field_settings[fieldName].value_type == 'retrybad') {

            // BOXES
            var bool_boxes_current = d3.select(".boolean_boxes_retry-bad")
                .selectAll(".bool_boxes_rect_retry-bad")
                .data(trimmed_data, function(d) {
                    return d.pcap_secs
                })

            // exit 
            bool_boxes_current.exit().remove()


            // update
            if (transition_bool) {
                bool_boxes_current.transition().duration(zoom_duration).attr('x', scaled('pcap_secs'));
            } else {
                bool_boxes_current.attr('x', scaled('pcap_secs'));
            }

            // enter
            enter_retrybad_boxes_by_dataset(bool_boxes_current)

            // PERCENT CHART
            d3.selectAll(".percent_area")
                .attr("d", function(d) {
                    return retrybad_percent_area(d);
                })
        }


    })
}

// helper functions for update
function trim_by_pcap_secs(data) {
    // slice dataset based on desired min/max pcap milliseconds
    var domain = state.scales['pcap_secs'].domain();
    return data.slice(binary_search_by_pcap_secs(data, domain[0]), binary_search_by_pcap_secs(data, domain[1]));
}


function zoomOut() {
    // get last element from the zoom stack
    var k = zoom_stack.pop();
    if (k) {
        state.scales['pcap_secs'].domain(k)
    } else {
        state.scales['pcap_secs'].domain(state.scales['pcap_secs_fixed'].domain())
    }
    // update brush domain and visible extent
    brush.extent(state.scales['pcap_secs'].domain())
    d3.selectAll(".brush").call(brush)

    update_pcaps_domain(state.scales['pcap_secs'].domain(), true)
}

var clicks = 0;
var event_list = [];

// helper functions for selection
function draw_hidden_rect_for_mouseover(svg, fieldName) {

    var click_timeout;
    var dragging = false;
    var mouse_start_pos;

    var drag_metrics = {
        x_start: [],
        x_diff: 0
    };

    svg.append('rect')
        .attr('width', dimensions.width.chart)
        .attr('height', dimensions.height.per_chart)
        .attr("class", "plotRect")
        .style('fill', 'none')
        .style('pointer-events', 'all')
        .on('mouseover', function() {
            d3.selectAll(".focus").classed("hidden", false)
        })
        .on('mouseout', function() {
            var x = d3.mouse(this)[0];
            if (x < state.scales['pcap_secs'].range()[0] ||
                x > state.scales['pcap_secs'].range()[1]) {
                d3.select('#tooltip').classed("hidden", true)
                d3.selectAll(".focus").classed("hidden", true)
            }
        })
        .on('mousedown', function() {
            event_list.push('mousedown')
            mouse_start_pos = d3.mouse(this)[0]
            d3.event.preventDefault()
        })
        .on('mouseup', function() {
            event_list.push('mouseup')
                // end of drag
            if (dragging == true) {
                d3.selectAll(".drag_rect").transition().duration(zoom_duration).attr("x", 0).attr("width", dimensions.width.chart)
                zoom_stack[zoom_stack.length] = state.scales['pcap_secs'].domain();

                // define new domain, and update
                if (drag_metrics.x_diff > 0) {
                    var newDomain = [
                        state.scales['pcap_secs'].invert(mouse_start_pos),
                        state.scales['pcap_secs'].invert(d3.mouse(this)[0])
                    ];
                } else {
                    var newDomain = [
                        state.scales['pcap_secs'].invert(d3.mouse(this)[0]),
                        state.scales['pcap_secs'].invert(mouse_start_pos)
                    ];
                }

                state.scales['pcap_secs'].domain(newDomain)
                brush.extent(newDomain)
                d3.selectAll(".brush").call(brush)

                update_pcaps_domain(newDomain, true)
                drag_metrics = {
                    x_start: [],
                    x_diff: 0
                }

                d3.selectAll(".drag_rect").transition().delay(500).attr("opacity", 0).attr("x", 0).attr("width", 0);
                var timeout2 = window.setTimeout(hide_element, 500, '.drag_rect')
                dragging = false;
                event_list = [];
                clicks = 0;
                mouse_start_pos = 0;
            } else if (event_list[event_list.length - 2] == 'mousedown') {
                clicks++
                if (clicks == 1) {
                    //click_timeout = window.setTimeout(on_click(d3.mouse(this), fieldName), 5000);
                    click_timeout = window.setTimeout(on_click, 200, d3.mouse(this), fieldName);
                } else {
                    window.clearTimeout(click_timeout);
                    zoomOut()
                    event_list = [];
                    clicks = 0;
                }
            }
        })
        .on('mousemove', function() {
            event_list.push("mousemove")
            if (event_list.indexOf('mousedown') != -1) {
                if (dragging == true) {
                    drag_metrics.x_diff = d3.mouse(this)[0] - mouse_start_pos
                    if (drag_metrics.x_diff > 0) {
                        d3.selectAll(".drag_rect").attr("width", drag_metrics.x_diff).attr("x", mouse_start_pos)
                    } else {
                        d3.selectAll(".drag_rect").attr("width", -drag_metrics.x_diff).attr("x", mouse_start_pos + drag_metrics.x_diff)
                    }
                } else if (event_list[event_list.length - 2] == 'mousemove') {
                    dragging = true;
                    d3.selectAll(".drag_rect").classed("hidden", false).attr("width", 0).attr("x", mouse_start_pos).attr("opacity", .1)
                }
            } else {

                d = find_packet(d3.mouse(this)[0], d3.mouse(this)[1], fieldName, true);
                if (!d) return;
                update_crosshairs(d);
            }
        })
}

function hide_element(element) {
    d3.selectAll(element).classed("hidden", true);
}

function on_click(location, field) {
    event_list = []
    clicks = 0;
    d = find_packet(location[0], location[1], field, false);
    if (!d) return;
    select_stream(d);
    update_crosshairs(d);
}

function draw_vertical(element, field) {
    element.append('line')
        .attr('class', 'x')
        .attr('y1', 0)
        .attr('y2', dimensions.height.per_chart * field_settings[field].height_factor);
}

function draw_crosshairs(element) {
    element.append('line')
        .attr('class', 'x')
        .attr('y1', 0)
        .attr('y2', dimensions.height.per_chart);

    element.append('line')
        .attr('class', 'y')
        .attr('x1', 0)
        .attr('x2', dimensions.width.chart);

    element.append('circle')
        .attr('class', 'y')
        .attr('r', 7);

    element.append('text')
        .attr('class', 'y1')
        .attr('dx', 8)
        .attr('dy', '-.5em');
}

function find_packet_boolean(x, y, field, lock) {
    if (x < state.scales['pcap_secs'].range()[0] ||
        x > state.scales['pcap_secs'].range()[1] ||
        y > total_height)
        return;

    var pcap_secs = state.scales['pcap_secs'].invert(x);
    var search_in = dataset;

    if (state.selected_data.stream && lock) {
        search_in = stream2packetsDict[state.selected_data.stream].values;
    }

    var idx = binary_search_by_pcap_secs(search_in, pcap_secs, 0);
    // d = closest_to_y(search_in, idx, x, y, scaled(field), field);

    // return d;
}

function find_packet(x, y, field, lock) {
    if (x < state.scales['pcap_secs'].range()[0] ||
        x > state.scales['pcap_secs'].range()[1] ||
        y > total_height)
        return;

    var pcap_secs = state.scales['pcap_secs'].invert(x);
    var search_in = dataset;

    if (state.selected_data.stream && lock) {
        search_in = stream2packetsDict[state.selected_data.stream].values;
    }

    var idx = binary_search_by_pcap_secs(search_in, pcap_secs, 0);
    d = closest_to_y(search_in, idx, x, y, scaled(field), field);

    return d;
}

function closest_to_y(search_in, idx, x, y, scaled_y, field) {
    var idx_range = 50;
    var x_range = 10;
    var scaled_x = scaled('pcap_secs');

    if (search_in.length > 1) {
        idx = Math.abs(x - scaled_x(search_in[idx - 1])) >
            Math.abs(x - scaled_x(search_in[idx])) ?
            idx : idx - 1;
    } else {
        idx = 0;
    }
    var begin = Math.max(0, idx - idx_range);
    var end = Math.min(search_in.length - 1, idx + idx_range);

    var closest_idx = idx;

    var min_x = Math.abs(x - scaled_x(search_in[idx]));
    var min_y = Math.abs(y - scaled_y(search_in[idx]));

    for (var i = begin; i <= end; i++) {
        if (Math.abs(x - scaled_x(search_in[i])) > x_range) {
            continue; // too far away
        }
        if (Math.abs(y - scaled_y(search_in[i])) < min_y ||
            (Math.abs(y - scaled_y(search_in[i])) == min_y &&
                Math.abs(x - scaled_x(search_in[i])) < min_x)) {
            min_x = Math.abs(x - scaled_x(search_in[i]));
            min_y = Math.abs(y - scaled_y(search_in[i]));
            closest_idx = i;
        }
    }

    return search_in[closest_idx];
}

function update_crosshairs(d) {
    var detailedInfo = d;

    for (var r_field in reticle) {
        var closest_x = scaled('pcap_secs')(d);
        var closest_y = scaled(r_field)(d);

        reticle[r_field].select('.x')
            .attr('transform', 'translate(' + closest_x + 10 + ',0)');


        reticle[r_field].select('circle.y')
            .attr('transform',
                'translate(' + closest_x + ',' + closest_y + ')');

        if (!isNaN(closest_y)) {
            reticle[r_field].select('.y')
                .attr('transform', 'translate(0,' + closest_y + ')');
        }
    }

    update_show_Tooltip(detailedInfo);
}

function update_show_Tooltip(data) {
    d3.select('#tooltip')
        .classed('hidden', false)
        .selectAll(".tooltipValues")
        .data(availableMetrics)
        .text(function(k) {
            if (k == "streamId") {
                return k + ": " + to_visible_stream_key(data[k]);
            }
            if (k == "ta" || k == "ra") {
                return k + ": " + addresses[data[k]].name
            }
            return k + ": " + data[k]
        });
}

function highlight_stream(d) {
    d3.selectAll(".legend").classed("selected_downstream", false).classed("selected_upstream", false)

    // to do - limit these?
    d3.selectAll(".selected_downstream").classed("selected_downstream", false).attr("height", dimensions.height.per_chart * dimensions.height.bar_factor_unselected)
    d3.selectAll(".selected_upstream").classed("selected_upstream", false).attr("height", dimensions.height.per_chart * dimensions.height.bar_factor_unselected)
    d3.selectAll(".selected_partialMatch_downstream").classed("selected_partialMatch_downstream", false).attr("height", dimensions.height.per_chart * dimensions.height.bar_factor_unselected)
    d3.selectAll(".selected_partialMatch_upstream").classed("selected_partialMatch_upstream", false).attr("height", dimensions.height.per_chart * dimensions.height.bar_factor_unselected)

    if (d.streamId != "badpacket---badpacket") {
        d3.selectAll(".selected_bad").classed("selected_bad", false);
        d3.selectAll(".stream_badpacket---badpacket").filter('.legend').classed("selected_bad", false);

        if (stream2packetsDict[d.streamId].direction == "upstream") {

            d3.selectAll(".stream_" + d.streamId).classed("selected_upstream", true).attr("height", dimensions.height.per_chart * dimensions.height.bar_factor_selected)
            d3.selectAll(".stream_" + complement_stream_id(d.streamId)).classed("selected_downstream", true).attr("height", dimensions.height.per_chart * dimensions.height.bar_factor_selected)
            d3.selectAll(".ta_" + d.ta).classed("selected_partialMatch_upstream", true).attr("height", dimensions.height.per_chart * dimensions.height.bar_factor_selected);
            d3.selectAll(".ra_" + d.ra).classed("selected_partialMatch_upstream", true).attr("height", dimensions.height.per_chart * dimensions.height.bar_factor_selected);

        } else {
            d3.selectAll(".stream_" + d.streamId).classed("selected_downstream", true).attr("height", dimensions.height.per_chart * dimensions.height.bar_factor_selected)
            d3.selectAll(".stream_" + complement_stream_id(d.streamId)).classed("selected_upstream", true).attr("height", dimensions.height.per_chart * dimensions.height.bar_factor_selected)
            d3.selectAll(".ta_" + d.ta).classed("selected_partialMatch_downstream", true).attr("height", dimensions.height.per_chart * dimensions.height.bar_factor_selected)
            d3.selectAll(".ra_" + d.ra).classed("selected_partialMatch_downstream", true).attr("height", dimensions.height.per_chart * dimensions.height.bar_factor_selected)
        }
    } else {
        d3.selectAll(".badpacket").classed("selected_bad", true);
        d3.selectAll(".stream_badpacket---badpacket").filter('.legend').classed("selected_bad", true);
    }

}

function select_stream(d) {
    // if new stream selected, update view & selected stream
    if (!state.selected_data.stream || d.streamId != state.selected_data.stream) {

        // need to clear because from the legend the user can click on another stream even when a stream is "locked"
        // which is not possible from the points since you can only mouseover your state.selected_data.stream

        state.selected_data.stream = d.streamId;
        if (stream2packetsDict[d.streamId].direction == "upstream") {
            state.selected_data.access = d.ta;
            state.selected_data.station = d.ra;
        } else {
            state.selected_data.access = d.ra;
            state.selected_data.station = d.ta;
        }
        highlight_stream(d);
        butter_bar('Locked to: ' + to_visible_stream_key(d.streamId));
    } else {
        d3.selectAll(".selected_downstream").classed("selected_downstream", false);
        d3.selectAll(".selected_upstream").classed("selected_upstream", false);
        d3.selectAll(".selected_partialMatch_downstream").classed("selected_partialMatch_downstream", false);
        d3.selectAll(".selected_partialMatch_upstream").classed("selected_partialMatch_upstream", false);
        d3.selectAll(".bad").classed("selected_bad", false);
        state.selected_data.stream = null;
        state.selected_data.access = null;
        state.selected_data.station = null;

        d3.selectAll(".bool_boxes_rect_retry-bad")
            .attr('height', dimensions.height.per_chart * dimensions.height.bar_factor_unselected)

        butter_bar('Unlocked')
    }
}

// helper functions for time formatting
function hourMinuteMilliseconds(d) {
    return d3.time.format("%H:%M:%S")(new Date(d * 1000))
}

function milliseconds(d) {
    return d3.time.format("%L")(new Date(d * 1000))
}
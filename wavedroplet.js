"use strict";

/*
Possible Next Steps:

Switch to Canvas for all but overview chart: faster than SVG, major advantage of SVG is selecting elements but we're not using that feature because of doing binary search instead to find closest point
      * alternatively, switch to voronoi to manage selecting nearest point: http://bl.ocks.org/mbostock/8033015, or just use points themselves?

Could use an adjacency matrix for mac addresses to see what's talking to what - a version is checked into zanarmstrong's wavedroplet repo

Turn overview histogram into stacked histogram, with colors to show bad/retry/good packets

Identify streams with numbers instead of strings to speed up code, dictionary for visible

Zooming sometimes buggy

Make everything faster!
*/

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
        left: 50,
        top: 30
    },
    height: {
        per_chart: 0,
        overview: 80,
        x_axis: 20,
        above_charts: 5,
        below_charts: 10,
        tooltip: 15,
        bar_height_unselected: 12,
        bar_height_selected: 14,
        split_factor: .4,
        butter_bar: 30,
        cum_height: 0
    },
    width: {
        chart: 0,
        y_axis: 60,
        sidebar: 80,
        right_labels: 200
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
        'height_factor': 1,
    },
    'seq': {
        'value_type': 'number',
        'scale_type': 'linear',
        'height_factor': 1,
        'translate_label': 60,
        'chart_height': 120
    },
    'rate': {
        'value_type': 'number',
        'scale_type': 'linear',
        'height_factor': 1,
        'translate_label': 60,
        'chart_height': 100
    },
    'retry_bad': {
        'value_type': 'stringbox',
        'scale_type': 'linear',
        'height_factor': .54,
        'translate_label': 60,
        'chart_height': 60,
        'element_height': dimensions.height.bar_height_selected + 2
    },
    'retry': {
        'value_type': 'boolean',
        'scale_type': 'linear',
        'height_factor': dimensions.height.split_factor,
        'translate_label': 30,
        'chart_height': 40,
        'element_height': 16,
    },
    'bad': {
        'value_type': 'boolean',
        'scale_type': 'linear',
        'height_factor': dimensions.height.split_factor,
        'translate_label': 30,
        'chart_height': 40,
        'element_height': dimensions.height.bar_height_selected + 2,
    },
    'bw': {
        'value_type': 'boolean',
        'scale_type': 'linear',
        'height_factor': dimensions.height.split_factor,
        'translate_label': 30,
        'chart_height': 40
    },
    // note - spatial streams is actually values of 1 and 2, rather than 0 and 1 - this works, but is a hack
    'spatialstreams': {
        'value_type': 'boolean',
        'scale_type': 'linear',
        'height_factor': .5,
        'translate_label': 84,
        'chart_height': 60,
        'element_height': dimensions.height.bar_height_selected + 2,
    },
    'streamId': {
        'value_type': 'string',
        'scale_type': 'linear',
        'height_factor': 1,
        'translate_label': 60,
        'chart_height': 200,
        'element_height': 5,
    },
    'typestr': {
        'value_type': 'stringbox',
        'scale_type': 'linear',
        'height_factor': 1,
        'translate_label': 60,
        'chart_height': 200,
        'element_height': dimensions.height.bar_height_selected + 2,
    }
}

// complete selectable metrics
for (var i in selectableMetrics) {
    if (!field_settings[selectableMetrics[i]]) {
        field_settings[selectableMetrics[i]] = {
            'value_type': 'number',
            'scale_type': 'linear',
            'height_factor': 1,
            'translate_label': 100,
            'chart_height': 100
        }
    }
}

// GLOBAL VARIABLES

// TODO: better handling of variables, less reliance on global variables

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
    },
    /* If you type in the console:
            state.filter.func = function(d){if(d["typestr"] == "04 ProbeReq"){return true} else {return false}}"
            update_pcaps_domain(state.scales['pcap_secs'].domain(), false)
       you can filter the displayed points to any particular subset you want (in this case, typestr that equal "04 ProbeReq")

       Note that this does not affect the cross-filter which will adjust to any dataset
    */
    filter: {
        func: "",
        "field": 0,
        "value": 0,
        "filteredData": []
    }
}

var reticle = {}; // dict[field; crosshair]
var number_of_packets;

// data structures
var dataset; // all packets, sorted by pcap_secs
var stream2packetsDict = {}; // look up values and direction by streamId
var ordered_strings = {
    "streamId": {},
    "typestr": {},
    "retry_bad": {
        'bad': 0,
        'retry': 1,
        'good': 2
    }
}
var ordered_arrays = {
    "streamId": [],
    "typestr": [],
    "retry_bad": ['bad', 'retry', 'good'],
    "streamId_legend": [],
}

var addresses = {
        "badpacket": {
            "name": "bad_packet"
        },
        "null": {
            "name": "null"
        }
    } // look up dictionary for alias name and direction by mac address
var histogramPacketNum = [] // array to be used to create overview histogram
var dict_by_ms = {} // faster to find packets on mouseover



// zoom variables
var zoom_duration = 750; // how long does transition on zoom take
var zoom_stack = []; // keep track of past zoom domain (pcap secs)

// on chart selection: drag, clicks, etc
var clicks = 0;
var event_list = [];

// other settings
var boolean_area = false // show boolean area charts

// x (pcap) axis for all charts
var pcapSecsAxis = d3.svg.axis()
    .tickFormat(milliseconds)
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
        if (!d) {
            return d;
        } else {
            return state.scales[name](d[name]);
        }
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
    dataset = json.js_packets;

    // get list of desired plots
    state.to_plot = get_query_param('to_plot');

    // sort by x values
    dataset.sort(function(x, y) {
        return x['pcap_secs'] - y['pcap_secs'];
    });

    dimensions.width.chart = total_width - dimensions.page.left - dimensions.width.y_axis - dimensions.width.sidebar;

    var x_range = [0, dimensions.width.chart];

    // set d3 scales
    add_scale('pcap_secs', x_range);
    state.to_plot.forEach(function(d) {
        add_scale(d, [field_settings[d].chart_height, 0])
    });

    // add fixed pcaps scale for header histogram nav chart
    state.scales['pcap_secs_fixed'] = d3.scale.linear().domain(state.scales['pcap_secs'].domain()).range(state.scales['pcap_secs'].range());

    // use data to update pcap secs
    pcapSecsAxis.scale(state.scales['pcap_secs']);

    // define array of all packet seconds, for use with histogram
    var packetSecs = []

    // set up addresses w/ aliases
    json.aliases
    for (var a in json.aliases) {
        addresses[a.replace(/:/gi, "")] = {
            "name": json.aliases[a]
        }
    }

    // get user selection regarding "1D Ack"
    var show_ack = get_query_param('ack')[0];

    dataset = dataset.filter(function(d) {

        //console.log(d.typestr, d.typestr == "1D ACK")
        if (show_ack == "false" & d.typestr == "1D ACK") {
            return false;
        } else {

            // replace ta/ra if packet is bad, or ta is null
            if (d.bad == 1) {
                d.ta = 'badpacket';
                d.ra = 'badpacket';
                d.retry_bad = 'bad';
            } else {
                if (d.retry == 1) {
                    d.retry_bad = 'retry';
                } else {
                    d.retry_bad = 'good';
                }
                // for good packets, create list of unique typestrings
                // worried this is slow :(, but the array should be small
                if (ordered_arrays.typestr.indexOf(d.typestr) == -1) {
                    ordered_arrays.typestr.push(d.typestr);
                }
            }
            if (d.ta == null) {
                d.ta = 'null';
            }

            // store time of packet
            packetSecs.push(d.pcap_secs)

            // string handling
            // to do -> use numeric dictionary for ta, ra, and stream ids instead of passing strings around (?)
            var streamId = to_stream_key(d);
            d.ta = d.ta.replace(/:/gi, "")
            d.ra = d.ra.replace(/:/gi, "")

            // use dsmode from each packet to define addresses as access or stations, use later to define streams as downstream/upstream
            // Logic: if dsmode = 2, then assign as downstream. If dsmode == 1, then assign as upstream. If dsmode
            // question: better to check if type exists, or overwrite as I'm doing here?

            if (!addresses[d.ra]) {
                addresses[d.ra] = {
                    "name": d.ra
                }
            }

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

            // add stream id to packet data
            d.streamId = streamId;

            // add packet to values in stream dictionary
            if (!stream2packetsDict[streamId]) {
                stream2packetsDict[streamId] = {
                    values: [d]
                };
                ordered_arrays['streamId'].push(streamId);
                ordered_arrays['streamId_legend'].push(streamId);
            } else {
                stream2packetsDict[streamId].values.push(d);
            }

            // dictionary sorted by time for faster scrollover (maybe?)
            if (!dict_by_ms[Math.floor(d.pcap_secs * 10)]) {
                dict_by_ms[Math.floor(d.pcap_secs * 10)] = [d]
            } else {
                dict_by_ms[Math.floor(d.pcap_secs * 10)].push(d)
            }
            return true;
        }
    })

    // use mac address station/access definitions to define per stream direction (upstream/downstream)
    ordered_arrays['streamId'].forEach(function(stream) {
        var k = to_ta_ra_from_stream_key(stream);
        if (addresses[k[0]].type == 'access' || addresses[k[1]].type == 'station') {
            stream2packetsDict[stream].direction = 'downstream';
            stream2packetsDict[stream].access = k[0];
            stream2packetsDict[stream].station = k[1]
        } else if (addresses[k[1]].type == 'access' || addresses[k[0]].type == 'station') {
            stream2packetsDict[stream].direction = 'upstream';
            stream2packetsDict[stream].access = k[1];
            stream2packetsDict[stream].station = k[0]
        } else {
            log(stream, 'direction not found')
        }
    })

    // set up histogram with 1000 bins
    // TODO: use better way to define number of bins?
    number_of_packets = packetSecs.length;
    histogramPacketNum = d3.layout.histogram().bins(1000)(packetSecs);

    // construct array to keep track of bin edges relative to dataset slices to aid in adding/removing points
    var dataSliceTracker = [];
    var count = 0;
    histogramPacketNum.forEach(function(d, i) {
        dataSliceTracker.push(count)
        count = count + d.y;
    })

    if (state.to_plot.indexOf("typestr") != -1) {
        // alphabetical (numeric) order for typestr, since then it's consistent from dataset to dataset
        ordered_arrays['typestr'].sort()
        ordered_arrays['typestr'].forEach(function(type, i) {
            ordered_strings['typestr'][type] = i;
        })
        ordered_strings['typestr']['undefined'] = ordered_arrays['typestr'].length;
        ordered_arrays['typestr'].push('undefined')
    }
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

// visualize the data
function draw() {
    add_butter_bar();

    add_overview();

    state.to_plot.forEach(function(d) {
        visualize(d)
    })

    add_legend();

    add_tooltip();
}

// overview chart at top: show packet distribution over time, and use for panning/zooming
function add_overview() {
    var max = 0;

    // find max bar height and use to set Y axis for overview chart
    histogramPacketNum.forEach(function(d) {
        if (d.y > max) {
            max = d.y;
        }
    })
    state.scales["packetNumPerTenth"] = d3.scale.linear().domain([0, max]).range([dimensions.height.overview, 0])

    // set up x and y axis
    var overviewYaxis = d3.svg.axis()
        .scale(state.scales['packetNumPerTenth'])
        .orient('right')
        .ticks(5);

    var overviewXaxis = d3.svg.axis()
        .scale(state.scales['pcap_secs_fixed'])
        .tickFormat(hourMinuteMilliseconds)
        .orient('bottom')
        .ticks(5);

    // start building the chart
    var height = dimensions.height.overview + dimensions.height.x_axis + dimensions.height.above_charts + dimensions.height.below_charts;
    var overviewChart = d3
        .select('body')
        .append('svg')
        .attr('id', 'histogramZoomNav')
        .attr('class', 'overviewChart')
        .attr('width', dimensions.width.chart + dimensions.width.y_axis + dimensions.width.sidebar)
        .attr('height', height)
        .append("g")
        .attr("transform", "translate(" + dimensions.page.left + ",0)");

    dimensions.height.cum_height = dimensions.height.cum_height + height;

    // append x and y axis
    overviewChart.append('g')
        .attr('class', 'axis x overview')
        .attr('transform', 'translate(0,' + dimensions.height.overview + ')')
        .call(overviewXaxis);

    overviewChart.append('g')
        .attr('class', 'axis y overview')
        .attr('transform', 'translate(' + (dimensions.width.chart) + ',0)')
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

    var svg = d3
        .select('body')
        .append('svg')
        .attr('id', 'butter_bar')
        .attr('width', dimensions.width.chart)
        .attr('height', dimensions.height.butter_bar);

    dimensions.height.cum_height = dimensions.height.cum_height + dimensions.height.butter_bar;

    svg.append('rect')
        .attr('id', 'butter_bar_box')
        .attr('width', dimensions.width.chart)
        .attr('height', dimensions.height.butter_bar)
        .style('fill', 'none');

    svg.append('text')
        .attr('id', 'butter_bar_msg')
        .attr('class', 'legend')
        .attr('x', dimensions.width.chart / 2)
        .attr('y', dimensions.height.butter_bar / 2 + 5)
        .style('fill', 'black')
        .style('font-size', 14);
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
        .duration(1000)
        .style('opacity', 0);
}

function add_legend() {
    var font_width = 6;
    var key_length = font_width * 40;
    var n_cols = Math.floor(dimensions.width.chart / key_length);
    var n_rows = Math.ceil(ordered_arrays['streamId'].length / n_cols)
    var legend_line_height = 24;

    // sort streams by number of packets per stream
    ordered_arrays['streamId_legend'].sort(function(a, b) {
        return stream2packetsDict[b].values.length - stream2packetsDict[a].values.length
    })

    d3.select('body')
        .append('svg')
        .attr('width', dimensions.width.chart)
        .attr('height', n_rows * 12)
        .attr('class', 'legendG')
        .append("g")
        .attr("transform", "translate(" + dimensions.page.left + ",0)")
        .selectAll(".legend")
        .data(ordered_arrays['streamId'])
        .enter()
        .append('text')
        .attr('class', function(d) {
            // for highlighting
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
            // get data needed to highight primary/secondary streams from stream name and addresses dictionary
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

function add_tooltip() {
    d3.select('#tooltip')
        .classed('hidden', true)
        .append("svg")
        .attr("width", 180)
        .attr("height", availableMetrics.length * dimensions.height.tooltip)
        .selectAll('.tooltipValues')
        .data(availableMetrics)
        .enter()
        .append("text")
        .attr("class", "tooltipValues")
        .attr("y", function(k, i) {
            return i * dimensions.height.tooltip + 10
        });
}

function update_show_Tooltip(data, location) {

    d3.select('#tooltip')
        .style('left', (location[0] + 50) + "px")
        .style('top', (location[1] + 20) + "px")
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

function visualize(field) {

    // set up main svg for plot
    var mainChart = d3.select('body')
        .append('svg')
        .attr('class', 'plot_' + field)
        .attr('width', dimensions.width.chart + dimensions.width.y_axis + dimensions.width.right_labels)
        .append("g")
        .attr("transform", "translate(" + dimensions.page.left + "," + dimensions.height.above_charts + ")");;

    // call function based on value type
    if (field_settings[field].value_type == 'number') {
        settings_numbers(field, mainChart)
    } else if (field_settings[field].value_type == 'boolean') {
        settings_boolean(field, mainChart);
    } else if (field_settings[field].value_type == 'string') {
        settings_strings(field, mainChart);
    } else if (field_settings[field].value_type == 'stringbox') {
        settings_stringbox(field, mainChart);
    }

    var height = field_settings[field].chart_height + dimensions.height.x_axis + dimensions.height.above_charts + dimensions.height.below_charts;
    d3.selectAll(".plot_" + field).attr("height", height)

    // keep track of cumulative height
    field_settings[field].svg_height = dimensions.height.cum_height + dimensions.height.above_charts;
    dimensions.height.cum_height = dimensions.height.cum_height + dimensions.height.above_charts + height;

    mainChart = mainChart.append('g').attr("class", field + "_container").attr("fill", "grey")

    var svg = mainChart
        .selectAll('.' + field + '_elements')
        .data(dataset, function(d) {
            return d.pcap_secs
        });

    // call function based on value type
    field_settings[field].enter_elements(svg, field);

    // x and y axis
    draw_metric_x_axis(mainChart, field);
    field_settings[field].y_axis_setup(mainChart, field);

    // Add crosshairs
    setup_crosshairs(field, mainChart);
    if (field_settings[field].element_type == 'box') {
        draw_vertical(reticle[field], field);
    } else {
        draw_crosshairs(reticle[field], field);
    }

    // append the rectangle to capture mouse movements
    draw_rect_for_zooming(mainChart, field_settings[field].chart_height);
    draw_hidden_rect_for_mouseover(mainChart, field);
}

// HELPER FUNCTIONS FOR VISUALIZATION

function setup_crosshairs(field, svg) {
    reticle[field] = svg.append('g')
        .attr("class", "focus")
        .style('display', null);
}

function enter_stringbox_boxes(svg, field) {

    svg.enter()
        .append('rect')
        .attr('x', scaled('pcap_secs'))
        .attr('y', string_y(field, ordered_strings[field], field_settings[field].element_height))
        .attr('width', 2)
        .attr('height', function(d) {
            if (determine_selected_class(d) == "" || determine_selected_class(d) == "badpacket") {
                return dimensions.height.bar_height_unselected
            } else {
                return dimensions.height.bar_height_selected
            }
        })
        .attr("class", function(d) {
            return 'boxes ' + field + "_elements " + ' ta_' + d.ta + ' ra_' + d.ra + ' stream_' + d.streamId + " " + determine_selected_class(d);
        })
}

function enter_boxes(svg, field) {

    if (field_settings[field] == 'boolean') {
        var y_func = function(d) {
            if (field != 'spatialstreams') {
                if (d[field] == 1) {
                    return 0
                } else {
                    return dimensions.height.bar_height_selected + 4
                }
            } else {
                if (d[field] == 2) {
                    return 0
                } else {
                    return dimensions.height.bar_height_selected + 4
                }
            }
        }
    } else {
        var y_func = string_y(field, ordered_strings[field], field_settings[field].element_height);
    }

    svg.enter()
        .append('rect')
        .attr('x', scaled('pcap_secs'))
        .attr('y', y_func)
        .attr('width', 2)
        .attr('height', function(d) {
            if (determine_selected_class(d) == "" || determine_selected_class(d) == "badpacket") {
                return dimensions.height.bar_height_unselected
            } else {
                return dimensions.height.bar_height_selected
            }
        })
        .attr("class", function(d) {
            return field + "_elements " + 'boxes' + " " + ' ta_' + d.ta + ' ra_' + d.ra + ' stream_' + d.streamId + " " + determine_selected_class(d);
        })
}

function determine_selected_class(d) {
    if (d.bad == 1) {
        return 'badpacket'
    } else if (!state.selected_data.stream || state.selected_data.stream == null) {
        return "";
    } else if (stream2packetsDict[d.streamId].direction == "upstream") {
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

function settings_boolean(field, svg) {

    // since boolean, set up strings for labels + crossovers
    if (field != 'spatialstreams') {
        ordered_strings[field] = {
            1: 0,
            0: 1
        };
        ordered_arrays[field] = [1, 0];
    } else {
        ordered_strings[field] = {
            2: 0,
            1: 1
        };
        ordered_arrays[field] = [2, 1];
    }

    // set up type specific metrics
    field_settings[field].x_metric = "x";
    field_settings[field].enter_elements = function(current, field) {
        return enter_boxes(current, field)
    };
    field_settings[field].element_type = "box"
    field_settings[field].y_axis_setup = function(svg, field) {
        return draw_string_y_axis(svg, field);
    }
}


function settings_stringbox(field, svg) {

    // update field settings appropriate for field type stringbox
    field_settings[field].x_metric = "x"
    field_settings[field].enter_elements = function(current, field) {
        return enter_boxes(current, field)
    }
    field_settings[field].chart_height = (ordered_arrays[field].length) * field_settings[field].element_height;
    field_settings[field].element_type = "box"
    field_settings[field].y_axis_setup = function(svg, field) {
        return draw_string_y_axis(svg, field);
    }
}


function cmp(a, b) {
    return (a || '').localeCompare(b || '');
}


function settings_strings(field, svg) {
    field_settings[field].x_metric = "cx"
    field_settings[field].enter_elements = function(current, field) {
        return enter_points(current, field, ordered_strings[field])
    }
    field_settings[field].element_type = "point"

    if (field == 'streamId') {
        // sort by AP mac address, then by station mac address
        ordered_arrays.streamId.sort(function(a, b) {
            var pa = stream2packetsDict[a];
            var pb = stream2packetsDict[b];
            if (pa.access != pb.access) {
                return cmp(pa.access, pb.access);
            } else {
                return cmp(pa.station, pb.station);
            }
        })

        // created ordered string list for streamId
        if (state.to_plot.indexOf("streamId") != -1) {
            ordered_arrays['streamId'].forEach(function(stream, i) {
                ordered_strings['streamId'][stream] = i;
            })
        }

        field_settings[field].y_axis_setup = function(svg, field) {
            return draw_string_y_axis_streamId(svg, field);
        }
    } else {
        field_settings[field].y_axis_setup = function(svg, field) {
            return draw_string_y_axis(svg, field);
        }
    }

    field_settings[field].chart_height = ordered_arrays[field].length * field_settings[field].element_height;
}

function settings_numbers(field, svg) {
    // for circles
    field_settings[field].x_metric = "cx"
    field_settings[field].enter_elements = function(current, field) {
        return enter_points(current, field);
    }
    field_settings[field].element_type = "point"
    field_settings[field].y_axis_setup = function(svg, field) {
        return draw_metric_y_axis(svg, field);
    }
}


function draw_rect_for_zooming(svg, height) {
    svg.append("rect")
        .attr("height", height)
        .attr("width", 0)
        .attr("x", 0)
        .attr("y", 0)
        .attr("class", "drag_rect hidden")
}

function enter_points(svg, field) {
    var cy_func = scaled(field);
    if (field_settings[field].value_type == 'string') {
        cy_func = string_y(field, ordered_strings[field], field_settings[field].element_height)
    }

    svg.enter()
        .append('circle')
        .attr('class', function(d) {
            return field + '_elements ' + ' points ' + ' ta_' + d.ta + ' ra_' + d.ra + ' stream_' + d.streamId + " " + determine_selected_class(d)
        })
        .attr('cx', scaled('pcap_secs'))
        .attr('cy', cy_func)
        .attr('r', 1.5);
}

function string_y(field, string_list, height_per_line) {
    return function(d) {
        var idx = string_list[d[field]];
        if (typeof(idx) == "undefined") {
            idx = string_list['undefined'];
        }
        return idx * height_per_line;
    }
}

function draw_metric_y_axis(svg, field) {
    var yAxis = d3.svg.axis()
        .scale(state.scales[field])
        .orient('right')
        .ticks(5);

    // y axis
    svg.append('g')
        .attr('class', 'axis y')
        .attr('transform', 'translate(' + (dimensions.width.chart) + ',0)')
        .call(yAxis);
}

function draw_string_y_axis_streamId(svg, field) {
    var access_point_list = [];
    var line_height = field_settings[field].element_height;

    ordered_arrays[field].forEach(function(d) {
        var access = stream2packetsDict[d].access;
        if (!addresses[access]) {
            addresses[access] = {};
        }
        if (!addresses[access].num_streams) {
            addresses[access].num_streams = 1;
            access_point_list.push(access)
        } else {
            addresses[access].num_streams++;
        }
    })

    var cumSum = 0;
    var cumSum2 = 0;
    var current_access_point;
    // y axis
    var axisgroup = svg.append('g')
        .attr('class', 'axis_string y ' + field)
        .selectAll(".labels_" + field)
        .data(access_point_list)
        .enter()

    axisgroup.append("text")
        .attr("x", dimensions.width.chart + 14)
        .attr("y", function(d, i) {
            var currentSum = cumSum;
            cumSum = cumSum + addresses[d].num_streams;
            return (currentSum + .5) * line_height;
            // return (i + .5) * line_height
        })
        .attr("fill", "grey")
        .attr("class", 'labels_' + field)
        .on("click", filterDataAccessPoint())
        .text(function(d) {
            return addresses[d].name
        })

    axisgroup.append("polyline").attr("points", function(d) {
        var currentSum = cumSum2;
        cumSum2 = cumSum2 + addresses[d].num_streams;
        return (dimensions.width.chart + 12) + "," + (currentSum * line_height) + " " +
            (dimensions.width.chart + 4) + "," + (currentSum * line_height) + " " +
            (dimensions.width.chart + 4) + "," + ((cumSum2 - 1) * line_height);
    }).attr("stroke", "grey").attr("fill", "none")
}

function draw_string_y_axis(svg, field) {
    var line_height = field_settings[field].element_height;

    // y axis
    svg.append('g')
        .attr('class', 'axis_string y ' + field)
        .selectAll(".labels_" + field)
        .data(ordered_arrays[field])
        .enter()
        .append("text")
        .attr("x", dimensions.width.chart + 5)
        .attr("y", function(d, i) {
            return (i + .5) * line_height
        })
        .attr("fill", "grey")
        .attr("class", 'labels_' + field)
        .on("click", filterData(field))
        .text(function(d) {
            if (field == 'streamId') {
                return to_visible_stream_key(d)
            } else {
                return d
            }
        })
}


function filterDataAccessPoint() {
    return function(d) {
        console.log(d)
        if (state.filter.value == d) {
            state.filter.func = "";
            state.filter.value = null;
            state.filter.field = null;
            state.filter.filteredData = dataset;
            d3.selectAll('.labels_streamId').classed("selected_label", false)

        } else {
            d3.selectAll('.selected_label').classed("selected_label", false)
            d3.select(this).classed("selected_label", true)
            state.filter.value = d;
            state.filter.field = "access_point";
            state.filter.func = function(k) {
                if (k.ta == d || k.ra == d) {
                    return true;
                } else {
                    return false;
                }
            };
            state.filter.filteredData = dataset.filter(state.filter.func)
        }

        update_pcaps_domain(state.scales['pcap_secs'].domain(), false);
    }
}


function filterData(field) {
    return function(d) {
        if (state.filter.value == d) {
            state.filter.func = "";
            state.filter.value = null;
            state.filter.field = null;
            state.filter.filteredData = dataset;
            d3.selectAll(".labels_" + field).classed("selected_label", false)

        } else {
            state.filter.value = d;
            state.filter.field = field;
            state.filter.func = function(k) {
                if (k[field] == d) {
                    return true;
                } else {
                    return false;
                }
            };
            state.filter.filteredData = dataset.filter(state.filter.func)
            d3.selectAll(".selected_label").classed("selected_label", false)
            d3.select(this).classed("selected_label", true)
        }
        update_pcaps_domain(state.scales['pcap_secs'].domain(), false);
    }
}



function draw_metric_x_axis(svg, field) {

    // title for plot
    svg.append("text")
        .attr('transform', 'translate(-10,' + field_settings[field].translate_label + ') rotate(-90)')
        .attr("class", "text-label")
        .text(field);

    // x axis
    var xaxis = svg.append('g')
        .attr('class', 'axis x metric')
        .attr('transform', 'translate(0,' + (field_settings[field].chart_height) + ')')

    xaxis.call(pcapSecsAxis);
}

function update_pcaps_domain(newDomain, transition_bool) {

    // set x-axis scale to new domain
    state.scales['pcap_secs'].domain(newDomain);
    // update all x-axis with new scale (except overview)
    d3.selectAll(".axis.x.metric").call(pcapSecsAxis);

    // trim dataset to just relevant time period
    if (state.filter.func != "") {
        var trimmed_data = trim_by_pcap_secs(state.filter.filteredData);
    } else {
        var trimmed_data = trim_by_pcap_secs(dataset);
    }

    // for each chart: select w/ new dataset, then exit/enter/update
    // todo: tighten these functions
    state.to_plot.forEach(function(field) {

        // select
        var current = d3.select("." + field + "_container")
            .selectAll("." + field + "_elements")
            .data(trimmed_data, function(d) {
                return d.pcap_secs
            })

        // exit
        current.exit().remove()

        // update
        if (transition_bool) {
            current.transition().duration(zoom_duration).attr(field_settings[field].x_metric, scaled('pcap_secs'));
        } else {
            current.attr(field_settings[field].x_metric, scaled('pcap_secs'));
        }

        // enter
        field_settings[field].enter_elements(current, field);
    })
}

// UPDATE HELPER FUNCTIONS
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

// helper functions for selection - currently only implemented on point charts
function draw_hidden_rect_for_mouseover(svg, field) {

    var click_timeout; // to call/cancel timeout for clicks vs double clicks
    var dragging = false; // during drag or not
    var mouse_start_pos; // for each drag, where did the mouse start

    // keeping track of change in x over drag from starting point
    var x_diff = 0;

    // add rectangle to monitor mouse events
    svg.append('rect')
        .attr('width', dimensions.width.chart)
        .attr('height', field_settings[field].chart_height)
        .attr("class", "plotRect")
        .style('fill', 'none')
        .style('pointer-events', 'all')
        .on('mouseover', function() {
            // show crosshairs
            d3.selectAll(".focus").classed("hidden", false)
        })
        .on('mouseout', function() {
            hide_if_out_of_range(d3.mouse(this)[0])
        })
        .on('mousedown', function() {
            // keep track of events
            event_list.push('mousedown')

            // track start position, in case of drag
            mouse_start_pos = d3.mouse(this)[0]

            d3.event.preventDefault()
        })
        .on('mouseup', function() {
            event_list.push('mouseup')

            // end of drag
            if (dragging == true) {
                end_drag(x_diff > 0, mouse_start_pos, d3.mouse(this)[0]);

                // clear during drag metrics
                x_diff = 0
                dragging = false;
                event_list = [];
                clicks = 0;
                mouse_start_pos = 0;
            } else if (event_list[event_list.length - 2] == 'mousedown') {
                clicks++
                if (clicks == 1) {
                    click_timeout = window.setTimeout(on_click, 200, d3.mouse(this), field); // plan for single click
                } else {
                    // if double click
                    window.clearTimeout(click_timeout); // cancel single click
                    zoomOut()

                    // reset
                    event_list = [];
                    clicks = 0;
                }
            }
        })
        .on('mousemove', function() {
            event_list.push("mousemove")
            if (event_list.indexOf('mousedown') != -1) {
                if (dragging == true) {

                    // continue drag
                    x_diff = d3.mouse(this)[0] - mouse_start_pos
                    if (x_diff > 0) {
                        d3.selectAll(".drag_rect").attr("width", x_diff).attr("x", mouse_start_pos)
                    } else {
                        d3.selectAll(".drag_rect").attr("width", -x_diff).attr("x", mouse_start_pos + x_diff)
                    }
                } else if (event_list[event_list.length - 2] == 'mousemove') {

                    // start drag
                    dragging = true;
                    d3.selectAll(".drag_rect").classed("hidden", false).attr("width", 0).attr("x", mouse_start_pos).attr("opacity", .1)
                }
            } else {
                // no drag, hover over nearest packet
                var d = find_packet(d3.mouse(this)[0], d3.mouse(this)[1], field, true);
                if (!d) return;
                update_crosshairs(d, true, field);
            }
        })
}

function end_drag(positive_diff, mouse_start, mouse_x) {
    d3.selectAll(".drag_rect").transition().duration(zoom_duration).attr("x", 0).attr("width", dimensions.width.chart)
    zoom_stack[zoom_stack.length] = state.scales['pcap_secs'].domain();

    // define new domain, and update
    if (positive_diff) {
        var newDomain = [
            state.scales['pcap_secs'].invert(mouse_start),
            state.scales['pcap_secs'].invert(mouse_x)
        ];
    } else {
        var newDomain = [
            state.scales['pcap_secs'].invert(mouse_x),
            state.scales['pcap_secs'].invert(mouse_start)
        ];
    }

    // use new domain to update
    state.scales['pcap_secs'].domain(newDomain)
    brush.extent(newDomain)
    d3.selectAll(".brush").call(brush)

    update_pcaps_domain(newDomain, true)

    // remove drag rectangle from view
    d3.selectAll(".drag_rect").transition().delay(500).attr("opacity", 0).attr("x", 0).attr("width", 0);
    var timeout2 = window.setTimeout(hide_element, 500, '.drag_rect')
}

function hide_if_out_of_range(x) {
    d3.select('#tooltip').classed("hidden", true)
    d3.selectAll(".focus").classed("hidden", true)
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
    update_crosshairs(d, false, field);
}

function draw_vertical(element, field) {
    element.append('line')
        .attr('class', 'x')
        .attr('y1', 0)
        .attr('y2', field_settings[field].chart_height);

    element.append('line')
        .attr('class', 'cross-line')
        .attr('x1', 0)
        .attr('x2', dimensions.width.chart);
}

function draw_crosshairs(element, field) {
    element.append('line')
        .attr('class', 'x')
        .attr('y1', 0)
        .attr('y2', field_settings[field].chart_height);

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


function string_translate(field) {
    return function(d) {
        return ordered_strings[field][d[field]] * field_settings[field].element_height;
    }
}

function find_packet(x, y, field, lock) {
    if (x < state.scales['pcap_secs'].range()[0] ||
        x > state.scales['pcap_secs'].range()[1] ||
        y > total_height)
        return;

    var pcap_secs = state.scales['pcap_secs'].invert(x);


    if (state.selected_data.stream && lock) {
        if (state.filter.func == "") {
            var search_in = stream2packetsDict[state.selected_data.stream].values;
        } else {
            // todo: this might be really slow
            var search_in = stream2packetsDict[state.selected_data.stream].values.filter(state.filter.func);
        }
    } else if (state.filter.func == "") {
        // search in closest 100ms of data points
        var search_in = dict_by_ms[Math.floor(pcap_secs * 10)];
    } else {
        var search_in = state.filter.filteredData;
    }

    var idx = binary_search_by_pcap_secs(search_in, pcap_secs, 0);
    if (field_settings[field].type == 'stringbox' || field == 'streamId' || field_settings[field].type == 'boolean') {
        var translate_y_func = string_translate(field);
        d = closest_to_y(search_in, idx, x, y, translate_y_func, field);
    } else {
        d = closest_to_y(search_in, idx, x, y, scaled(field), field);
    }
    return d;
}

function closest_to_y(search_in, idx, x, y, scaled_y, field) {
    var idx_range = 50;
    var x_range = 30;
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

function update_crosshairs(d, tooltip, field) {
    // todo: make this work for stringbox and stringid
    var detailedInfo = d;

    for (var r_field in reticle) {

        var closest_x = scaled('pcap_secs')(d);

        if (field_settings[r_field].value_type == 'stringbox' || r_field == 'streamId' || field_settings[r_field].value_type == 'boolean') {
            var element_height = field_settings[r_field].element_height;
            var closest_y = ordered_strings[r_field][d[r_field]] * element_height;

            reticle[r_field].select('.cross-line')
                .attr('transform',
                    'translate(0,' + (closest_y + element_height / 2) + ')');

        } else {
            var closest_y = scaled(r_field)(d);
        }
        reticle[r_field].select('.x')
            .attr('transform', 'translate(' + closest_x + 10 + ',0)');

        reticle[r_field].select('circle.y')
            .attr('transform',
                'translate(' + closest_x + ',' + closest_y + ')');

        if (!isNaN(closest_y)) {
            reticle[r_field].select('.y')
                .attr('transform', 'translate(0,' + closest_y + ')');
        } else {
            // reverse from d value to y value? --> for boolean, strings, etc
        }

        if (tooltip & r_field == field) {
            update_show_Tooltip(detailedInfo, [closest_x + dimensions.page.left, closest_y + field_settings[field].svg_height]);
        }
    }


}

function highlight_stream(d) {
    // todo: can this be done more efficiently?
    d3.selectAll(".legend").classed("selected_downstream", false).classed("selected_upstream", false)

    // remove current selections
    d3.selectAll(".selected_downstream").classed("selected_downstream", false).attr("height", dimensions.height.bar_height_unselected)
    d3.selectAll(".selected_upstream").classed("selected_upstream", false).attr("height", dimensions.height.bar_height_unselected)
    d3.selectAll(".selected_partialMatch_downstream").classed("selected_partialMatch_downstream", false).attr("height", dimensions.height.bar_height_unselected)
    d3.selectAll(".selected_partialMatch_upstream").classed("selected_partialMatch_upstream", false).attr("height", dimensions.height.bar_height_unselected)

    if (d.streamId != "badpacket---badpacket") {
        // remove bad selections
        d3.selectAll(".badpacket").classed("selected_bad", false);
        d3.selectAll(".stream_badpacket---badpacket").filter('.legend').classed("selected_bad", false);

        if (stream2packetsDict[d.streamId].direction == "upstream") {

            d3.selectAll(".stream_" + d.streamId).classed("selected_upstream", true).attr("height", dimensions.height.bar_height_selected)
            d3.selectAll(".stream_" + complement_stream_id(d.streamId)).classed("selected_downstream", true).attr("height", dimensions.height.bar_height_selected)
            d3.selectAll(".ta_" + d.ta).classed("selected_partialMatch_upstream", true).attr("height", dimensions.height.bar_height_selected);
            d3.selectAll(".ra_" + d.ra).classed("selected_partialMatch_upstream", true).attr("height", dimensions.height.bar_height_selected);

        } else {
            d3.selectAll(".stream_" + d.streamId).classed("selected_downstream", true).attr("height", dimensions.height.bar_height_selected)
            d3.selectAll(".stream_" + complement_stream_id(d.streamId)).classed("selected_upstream", true).attr("height", dimensions.height.bar_height_selected)
            d3.selectAll(".ta_" + d.ta).classed("selected_partialMatch_downstream", true).attr("height", dimensions.height.bar_height_selected)
            d3.selectAll(".ra_" + d.ra).classed("selected_partialMatch_downstream", true).attr("height", dimensions.height.bar_height_selected)
        }
    } else {
        // make "bad" selections
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
        // unselect everything!
        d3.selectAll(".selected_downstream").classed("selected_downstream", false);
        d3.selectAll(".selected_upstream").classed("selected_upstream", false);
        d3.selectAll(".selected_partialMatch_downstream").classed("selected_partialMatch_downstream", false);
        d3.selectAll(".selected_partialMatch_upstream").classed("selected_partialMatch_upstream", false);
        d3.selectAll(".badpacket").classed("selected_bad", false);
        state.selected_data.stream = null;
        state.selected_data.access = null;
        state.selected_data.station = null;

        butter_bar('Unlocked')
    }
}

// helper functions for time formatting
function hourMinuteMilliseconds(d) {
    return d3.time.format("%H:%M:%S")(new Date(d * 1000))
}

function milliseconds(d) {
    return d3.time.format("%Ss %Lms")(new Date(d * 1000))
}

"use strict";

/*
Possible Next Steps: 

Switch to Canvas for all but overview chart: faster than SVG, major advantage of SVG is selecting elements but we're not using that feature because of doing binary search instead to find closest point
      * alternatively, switch to voronoi to manage selecting nearest point: http://bl.ocks.org/mbostock/8033015

Could use an adjacency matrix for mac addresses to see what's talking to what - a version is checked into zanarmstrong's wavedroplet repo

Turn overview histogram into stacked histogram, with colors to show bad/retry/good packets

Identify streams with numbers instead of strings to speed up code, dictionary for visible
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
        left: 80,
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
        bar_height_selected: 15,
        split_factor: .4,
        butter_bar: 30,
    },
    width: {
        chart: 0,
        y_axis: 60,
        sidebar: 180,
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
        'chart_height': 150
    },
    'rate': {
        'value_type': 'number',
        'scale_type': 'linear',
        'height_factor': 1,
        'translate_label': 60,
        'chart_height': 100
    },
    'retry-bad': {
        'value_type': 'retrybad',
        'scale_type': 'linear',
        'height_factor': .54,
        'translate_label': 60,
        'chart_height': 60
    },
    'retry': {
        'value_type': 'boolean',
        'scale_type': 'linear',
        'height_factor': dimensions.height.split_factor,
        'translate_label': 30,
        'chart_height': 40
    },
    'bad': {
        'value_type': 'boolean',
        'scale_type': 'linear',
        'height_factor': dimensions.height.split_factor,
        'translate_label': 30,
        'chart_height': 40
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
        'chart_height': 50
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
        'value_type': 'typestr',
        'scale_type': 'linear',
        'height_factor': 1,
        'translate_label': 60,
        'chart_height': 200,
        'element_height': 18,
    }
}

// complete selectable metrics 
for (var i in selectableMetrics) {
    if (!field_settings[selectableMetrics[i]]) {
        field_settings[selectableMetrics[i]] = {
            'value_type': 'number',
            'scale_type': 'linear',
            'height_factor': 1,
            'translate_label': 60,
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
    }
}

var reticle = {}; // dict[field; crosshair]
var number_of_packets;

// data structures
var dataset; // all packets, sorted by pcap_secs
var stream2packetsDict = {}; // look up values and direction by streamId
var ordered_strings = {
    "streamId": {},
    "typestr": {}
}
var ordered_arrays = {
    "streamId": [],
    "typestr": []
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

var j;

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
    j = json.aliases
    for (var a in json.aliases) {
        addresses[a.replace(/:/gi, "")] = {
            "name": json.aliases[a]
        }
    }

    // get user selection regarding "1D Ack"
    var show_ack = get_query_param('ack')[0];

    dataset.forEach(function(d) {

        // check for 1D ACK and skip, if appropriate
        if (!(show_ack == false & d.type_str == "1D ACK")) {

            // replace ta/ra if packet is bad, or ta is null
            if (d.bad == 1) {
                d.ta = 'badpacket';
                d.ra = 'badpacket';
            } else {
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
            } else {
                stream2packetsDict[streamId].values.push(d);
            }

            if (!dict_by_ms[Math.floor(d.pcap_secs * 10)]) {
                dict_by_ms[Math.floor(d.pcap_secs * 10)] = [d]
            } else {
                dict_by_ms[Math.floor(d.pcap_secs * 10)].push(d)
            }
        }
    })

    // use mac address station/access definitions to define per stream direction (upstream/downstream)
    ordered_arrays['streamId'].forEach(function(stream) {
        var k = to_ta_ra_from_stream_key(stream);
        if (addresses[k[0]].type == 'access' || addresses[k[1]].type == 'station') {
            stream2packetsDict[stream].direction = 'downstream';
        } else if (addresses[k[1]].type == 'access' || addresses[k[0]].type == 'station') {
            stream2packetsDict[stream].direction = 'upstream';
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

    // sort streams by number of packets per stream
    ordered_arrays['streamId'].sort(function(a, b) {
        return stream2packetsDict[b].values.length - stream2packetsDict[a].values.length
    })

    // created ordered string list for streamId
    if (state.to_plot.indexOf("streamId") != -1) {
        ordered_arrays['streamId'].forEach(function(stream, i) {
            ordered_strings['streamId'][stream] = i;
        })
    }

    if (state.to_plot.indexOf("typestr") != -1) {
        // alphabetical (numeric) order for typestr, since then it's consistent from dataset to dataset
        ordered_arrays['typestr'].sort(function(a, b) {
            return a - b
        })
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
        .orient('left')
        .ticks(5);

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

    // append x and y axis
    overviewChart.append('g')
        .attr('class', 'axis x overview')
        .attr('transform', 'translate(0,' + dimensions.height.overview + ')')
        .call(overviewXaxis);

    overviewChart.append('g')
        .attr('class', 'axis y overview')
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
                if (typeof(addresses[data[k]]) == undefined) {
                    console.log(data[k])
                }
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
        .attr('height', field_settings[field].chart_height + dimensions.height.x_axis + dimensions.height.above_charts + dimensions.height.below_charts)
        .append("g")
        .attr("transform", "translate(" + dimensions.page.left + "," + dimensions.height.above_charts + ")");;

    // call function based on value type
    if (field_settings[field].value_type == 'number') {
        visualize_numbers(field, mainChart)
    } else if (field_settings[field].value_type == 'boolean') {
        visualize_boolean(field, mainChart);
    } else if (field_settings[field].value_type == 'retrybad') {
        visualize_retrybad(mainChart);
    } else if (field_settings[field].value_type == 'string') {
        visualize_strings(field, mainChart);
    } else if (field_settings[field].value_type == 'typestr') {
        visualize_typestr(mainChart);
    }

}

// HELPER FUNCTIONS FOR VISUALIZATION

function visualize_boolean(field, svg) {

    // set up vertical boxes 
    var boolean_boxes = svg.append('g').attr("class", 'boolean_boxes_' + field).attr("fill", "grey")

    enter_boolean_boxes_by_dataset(field,
        boolean_boxes.selectAll('.bool_boxes_rect_' + field)
        .data(dataset, function(d) {
            return d.pcap_secs
        }));

    // x axis
    draw_metric_x_axis(svg, field);

    // Add crosshairs
    setup_crosshairs(field, svg)
    draw_vertical(reticle[field], field);

    // rect for zooming
    draw_rect_for_zooming(svg, field_settings[field].chart_height)
}

function setup_crosshairs(field, svg) {
    reticle[field] = svg.append('g')
        .attr("class", "focus")
        .style('display', null);
}

function visualize_retrybad(svg) {
    var boolean_boxes = svg.append('g').attr("class", 'boolean_boxes_retry-bad').attr("fill", "grey")

    // box charts
    enter_retrybad_boxes_by_dataset(
        boolean_boxes.selectAll('.bool_boxes_rect_retry-bad')
        .data(dataset, function(d) {
            return d.pcap_secs
        }));

    // To include dripping percent chart, uncomment the line below - also, fix spacing
    //draw_retrybad_percent_chart(svg);

    // x axis
    draw_metric_x_axis(svg, 'retry-bad');

    // Add crosshairs
    setup_crosshairs('retry-bad', svg)
    draw_vertical(reticle['retry-bad'], 'retry-bad');

    // zooming object
    draw_rect_for_zooming(svg, field_settings['retry-bad'].chart_height)
}

function enter_typestr_boxes(svg, string_list) {

    svg.enter()
        .append('rect')
        .attr('x', scaled('pcap_secs'))
        .attr('y', string_y('typestr', string_list, field_settings['typestr'].element_height))
        .attr('width', 2)
        .attr('height', function(d) {
            if (determine_selected_class(d) == "" || determine_selected_class(d) == "badpacket") {
                return dimensions.height.bar_height_unselected
            } else {
                return dimensions.height.bar_height_selected
            }
        })
        .attr("class", function(d) {
            return 'bool_boxes_typestr' + " " + ' ta_' + d.ta + ' ra_' + d.ra + ' stream_' + d.streamId + " " + determine_selected_class(d);
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

function enter_boolean_boxes_by_dataset(fieldName, svg) {

    svg.enter()
        .append('rect')
        .attr('x', scaled('pcap_secs'))
        .attr('y', function(d) {
            if (fieldName != 'spatialstreams') {
                if (d[fieldName] == 1) {
                    return 0
                } else {
                    return dimensions.height.bar_height_selected + 4
                }
            } else {
                if (d[fieldName] == 2) {
                    return 0
                } else {
                    return dimensions.height.bar_height_selected + 4
                }
            }
        })
        .attr('width', 2)
        .attr('height', function(d) {
            if (determine_selected_class(d) == "" || determine_selected_class(d) == "badpacket") {
                return dimensions.height.bar_height_unselected
            } else {
                return dimensions.height.bar_height_selected
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
                return dimensions.height.bar_height_selected + 4
            } else {
                return 2 * (dimensions.height.bar_height_selected + 4)
            }
        })
        .attr('width', 1)
        .attr('height', function(d) {
            // selected rectangles are taller/longer
            if (determine_selected_class(d) == "" || determine_selected_class(d) == "badpacket") {
                return dimensions.height.bar_height_unselected;
            } else {
                return dimensions.height.bar_height_selected;
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

function visualize_typestr(svg) {

    field_settings.typestr.chart_height = (ordered_arrays['typestr'].length + 1) * field_settings['typestr'].element_height;
    d3.selectAll(".plot_" + "typestr").attr("height", field_settings.typestr.chart_height +
        dimensions.height.x_axis +
        dimensions.height.above_charts +
        dimensions.height.below_charts);

    // set up vertical boxes 
    var boxes = svg.append('g').attr("class", 'typestr_boxes_' + 'typestr').attr("fill", "grey")

    // draw points
    enter_typestr_boxes(boxes.selectAll('.bool_boxes_typestr')
        .data(dataset, function(d) {
            return d.pcap_secs
        }),
        ordered_strings.typestr);

    // x and y axis
    draw_metric_x_axis(svg, 'typestr');
    draw_string_y_axis(svg, 'typestr', ordered_arrays['typestr'], field_settings['typestr'].element_height)

    // Add crosshairs
    setup_crosshairs('typestr', svg)
    draw_vertical(reticle['typestr'], 'typestr');

    // append the rectangle to capture mouse movements
    draw_rect_for_zooming(svg, field_settings.typestr.chart_height)
    draw_hidden_rect_for_mouseover(svg, 'typestr')

}

function visualize_strings(field, svg) {

    field_settings[field].chart_height = ordered_arrays[field].length * field_settings[field].element_height;
    d3.selectAll(".plot_" + field).attr("height", field_settings[field].chart_height +
        dimensions.height.x_axis +
        dimensions.height.above_charts +
        dimensions.height.below_charts)

    // draw points
    draw_points_strings(field, svg, ordered_strings[field]);

    // x and y axis
    draw_metric_x_axis(svg, field);
    if (field != 'streamId') {
        draw_string_y_axis(svg, field, ordered_arrays[field], field_settings[field].element_height)
    }
    // Add crosshairs
    setup_crosshairs(field, svg)
    draw_crosshairs(reticle[field], field);

    // append the rectangle to capture mouse movements
    draw_rect_for_zooming(svg, field_settings[field].chart_height)
    draw_hidden_rect_for_mouseover(svg, field)
}

function visualize_numbers(field, svg) {
    setup_crosshairs(field, svg)

    // draw points
    draw_points(field, svg);

    // x and y axis
    draw_metric_x_axis(svg, field);
    draw_metric_y_axis(svg, field);

    // Add crosshairs
    draw_crosshairs(reticle[field], field);

    // append the rectangle to capture mouse movements
    draw_rect_for_zooming(svg, field_settings[field].chart_height)
    draw_hidden_rect_for_mouseover(svg, field)
}

function draw_rect_for_zooming(svg, height) {
    svg.append("rect")
        .attr("height", height)
        .attr("width", 0)
        .attr("x", 0)
        .attr("y", 0)
        .attr("class", "drag_rect hidden")
}

function draw_points(fieldName, svg) {
    enter_points(
        svg.append('g')
        .attr("class", 'pcap_vs_' + fieldName + " metricChart")
        .attr("fill", 'grey')
        .selectAll('.points_numbers')
        .data(dataset, function(d) {
            return d.pcap_secs
        }),
        fieldName)

}

function enter_points(svg, fieldName) {
    svg.enter()
        .append('circle')
        .attr('class', function(d) {
            return 'points_numbers' + ' ta_' + d.ta + ' ra_' + d.ra + ' stream_' + d.streamId + " " + determine_selected_class(d)
        })
        .attr('cx', scaled('pcap_secs'))
        .attr('cy', scaled(fieldName))
        .attr('r', 1.5);
}

function draw_points_strings(fieldName, svg, string_list) {
    enter_points_strings(svg.append('g').attr("class", 'pcap_vs_' + fieldName + " metricChart")
        .attr("fill", 'grey')
        .selectAll('.points_strings')
        .data(dataset, function(d) {
            return d.pcap_secs
        }), string_list, fieldName)
}

function enter_points_strings(svg, string_list, fieldName) {
    svg.enter()
        .append('circle')
        .attr('class', function(d) {
            return 'points_strings' + ' ta_' + d.ta + ' ra_' + d.ra + ' stream_' + d.streamId + " " + determine_selected_class(d)
        })
        .attr('cx', scaled('pcap_secs'))
        .attr('cy', string_y(fieldName, string_list, field_settings[fieldName].element_height))
        .attr('r', 1.5);
}

function string_y(fieldName, string_list, height_per_line) {
    return function(d) {
        var idx = string_list[d[fieldName]];
        if (typeof(idx) == "undefined") {
            idx = string_list['undefined'];
        }
        return idx * height_per_line;
    }
}

function draw_metric_y_axis(svg, fieldName) {
    var yAxis = d3.svg.axis()
        .scale(state.scales[fieldName])
        .orient('left')
        .ticks(5);

    // y axis
    svg.append('g')
        .attr('class', 'axis y')
        //  .attr('transform', 'translate(' + (dimensions.width.chart) + ',0)')
        .call(yAxis);
}

function draw_string_y_axis(svg, field, string_list, line_height) {
    // y axis
    svg.append('g')
        .attr('class', 'axis_string y ' + field)
        .selectAll(".labels_" + field)
        .data(string_list)
        .enter()
        .append("text")
        .attr("x", dimensions.width.chart + 5)
        .attr("y", function(d, i) {
            return (i + .5) * line_height
        })
        .attr("class", '.labels_' + field)
        .text(function(d) {
            if (field == 'streamId') {
                return to_visible_stream_key(d)
            } else {
                return d
            }
        })
}


function draw_metric_x_axis(svg, fieldName) {
    // title for plot
    svg.append("text")
        .attr('transform', 'translate(-40,' + field_settings[fieldName].translate_label + ') rotate(-90)')
        .attr("class", "text-label")
        .text(fieldName);

    // x axis
    var xaxis = svg.append('g')
        .attr('class', 'axis x metric')
        .attr('transform', 'translate(0,' + (field_settings[fieldName].chart_height) + ')')

    xaxis.call(pcapSecsAxis);
}

function update_pcaps_domain(newDomain, transition_bool) {

    // set x-axis scale to new domain
    state.scales['pcap_secs'].domain(newDomain);
    // update all x-axis with new scale (except overview)
    d3.selectAll(".axis.x.metric").call(pcapSecsAxis);

    // trim dataset to just relevant time period
    var trimmed_data = trim_by_pcap_secs(dataset);

    // for each chart: select w/ new dataset, then exit/enter/update 
    // todo: tighten these functions
    state.to_plot.forEach(function(fieldName) {
        if (field_settings[fieldName].value_type == 'number') {
            // select
            var points = d3.selectAll('.pcap_vs_' + fieldName).selectAll('.points_numbers')
                .data(trimmed_data, function(d) {
                    return d.pcap_secs
                })

            // exit
            points.exit().remove();

            // update
            if (transition_bool) {
                points.transition().duration(zoom_duration).attr('cx', scaled('pcap_secs'))
            } else {
                points.attr('cx', scaled('pcap_secs'))
            }

            // enter
            enter_points(points, fieldName)

        }

        if (field_settings[fieldName].value_type == 'typestr') {
            // select
            var typestr_boxes_current = d3.select(".typestr_boxes_typestr")
                .selectAll(".bool_boxes_typestr")
                .data(trimmed_data, function(d) {
                    return d.pcap_secs
                })

            // exit 
            typestr_boxes_current.exit().remove()

            // update
            if (transition_bool) {
                typestr_boxes_current.transition().duration(zoom_duration).attr('x', scaled('pcap_secs'));
            } else {
                typestr_boxes_current.attr('x', scaled('pcap_secs'));
            }

            // enter
            enter_typestr_boxes(typestr_boxes_current, ordered_strings.typestr)

        }

        if (field_settings[fieldName].value_type == 'string') {
            // select
            var points = d3.selectAll('.pcap_vs_' + fieldName).selectAll('.points_strings')
                .data(trimmed_data, function(d) {
                    return d.pcap_secs
                })

            // exit
            points.exit().remove();

            // update
            if (transition_bool) {
                points.transition().duration(zoom_duration).attr('cx', scaled('pcap_secs'))
            } else {
                points.attr('cx', scaled('pcap_secs'))
            }

            // enter
            enter_points_strings(points, ordered_strings[fieldName], fieldName)
        }

        if (field_settings[fieldName].value_type == 'boolean') {
            // select
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

            // select
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
        }
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
function draw_hidden_rect_for_mouseover(svg, fieldName) {

    var click_timeout; // to call/cancel timeout for clicks vs double clicks
    var dragging = false; // during drag or not
    var mouse_start_pos; // for each drag, where did the mouse start

    // keeping track of change in x over drag from starting point
    var x_diff = 0;

    // add rectangle to monitor mouse events
    svg.append('rect')
        .attr('width', dimensions.width.chart)
        .attr('height', field_settings[fieldName].chart_height)
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
                    click_timeout = window.setTimeout(on_click, 200, d3.mouse(this), fieldName); // plan for single click
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
                var d = find_packet(d3.mouse(this)[0], d3.mouse(this)[1], fieldName, true);
                if (!d) return;
                update_crosshairs(d);
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
    if (x < state.scales['pcap_secs'].range()[0] ||
        x > state.scales['pcap_secs'].range()[1]) {
        d3.select('#tooltip').classed("hidden", true)
        d3.selectAll(".focus").classed("hidden", true)
    }
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
        .attr('y2', field_settings[field].chart_height);
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

    // search in closest 100ms of data points
    var search_in = dict_by_ms[Math.floor(pcap_secs * 10)];

    if (state.selected_data.stream && lock) {
        search_in = stream2packetsDict[state.selected_data.stream].values;
    }

    var idx = binary_search_by_pcap_secs(search_in, pcap_secs, 0);
    if (field == 'typestr' || field == 'streamId') {
        var translate_y_func = string_translate(field);
        d = closest_to_y(search_in, idx, x, y, translate_y_func, field);
    } else {
        d = closest_to_y(search_in, idx, x, y, scaled(field), field);
    }
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
    // todo: make this work for typestr and stringid
    var detailedInfo = d;

    for (var r_field in reticle) {
        var closest_x = scaled('pcap_secs')(d);
        if (r_field == 'typestr' || r_field == 'streamId') {
            var closest_y = ordered_strings[r_field][d[r_field]] * field_settings[r_field].element_height;
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
        }
    }

    update_show_Tooltip(detailedInfo);
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

        d3.selectAll(".bool_boxes_rect_retry-bad")
            .attr('height', dimensions.height.bar_height_unselected)

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
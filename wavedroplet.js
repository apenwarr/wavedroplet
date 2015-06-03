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

// set chart size dimensions
var sidebar_width = 180;
// set margin for set of charts
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
    },
    width: {
        chart: 0,
        y_axis: 60
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
    },
    'seq': {
        'value_type': 'number',
        'scale_type': 'linear',
    },
    'rate': {
        'value_type': 'number',
        'scale_type': 'linear',
    },
    'bad': {
        'value_type': 'boolean',
        'scale_type': 'linear'
    },
    'retry': {
        'value_type': 'boolean',
        'scale_type': 'linear'
    }
}

for (var i in selectableMetrics) {
    if (!field_settings[selectableMetrics[i]]) {
        field_settings[selectableMetrics[i]] = {
            'value_type': 'number',
            'scale_type': 'linear'
        }
    }
}

// global variables
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
var stream2packetsDict = {};
var stream2packetsArray = [];

// pcap axis
var pcapSecsAxis = d3.svg.axis()
    .tickFormat(hourMinuteMilliseconds)
    .orient('bottom')
    .ticks(5);

// set up brush and brushed function
var brush = d3.svg.brush()
    .on("brushend", function() {
        update_pcaps_domain(brush.empty() ? state.scales['pcap_secs_fixed'].domain() : brush.extent())
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

// get data & visualize
d3.json('/json/' + decodeURIComponent(get_query_param('key')[0]), function(error, json) {
    if (error) return console.error('error', error);

    var begin = new Date().getTime();

    // update title
    document.getElementById("title").innerHTML = json.filename;

    init(json);
    draw();

    var end = new Date().getTime();
    log('Spent on visualization ' + ((end - begin) / 1000) + ' sec.');
})

function init(json) {
    // TODO(katepek): Should sanitize here? E.g., discard bad packets?
    // Packets w/o seq?
    dataset = json.js_packets;

    state.to_plot = get_query_param('to_plot');

    // Leave only packets that have all the fields that we want to plot
    sanitize_dataset();

    dataset.sort(function(x, y) {
        return x['pcap_secs'] - y['pcap_secs'];
    });

    // TODO(katepek): Recalculate and redraw when resized
    dimensions.height.per_chart = Math.max((total_height - dimensions.height.overview - dimensions.page.top - (state.to_plot.length + 1) * (dimensions.height.above_charts + dimensions.height.below_charts + dimensions.height.x_axis)) / state.to_plot.length, 100);
    dimensions.width.chart = total_width - dimensions.page.left - dimensions.width.y_axis - sidebar_width;

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

    dataset.forEach(function(d) {
        if (d.bad == 1) {
            d.ta = 'bad_packet';
            d.ra = 'bad_packet';
        }
        // store time of packet
        packetSecs.push(d.pcap_secs)

        replace_address_with_alias(d, json.aliases);
        // track streams
        var streamId = to_stream_key(d, json.aliases);
        d.ta = d.ta.replace(/:/gi, "")
        d.ra = d.ra.replace(/:/gi, "")

        if (d.dsmode == 1) {
            d.access = d.ra;
            d.station = d.ta;
        } else {
            // treat 3 as if it were 2, since bad packets
            // treat 0 as if it were 2, since ta must be access point
            d.access = d.ta;
            d.station = d.ra;
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

function to_stream_key(d, aliases) {
    return d['ta'].replace(/:/g, '') + '---' + d['ra'].replace(/:/g, '');
}

function to_visible_stream_key(d) {
    return d.replace(/---/g, '→')
}

function to_css_stream_key(d) {
    return d.replace(/→/g, '---')
}

function replace_address_with_alias(d, aliases) {
    d['ta'] = aliases[d['ta']] || d['ta']
    d['ra'] = aliases[d['ra']] || d['ra']
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

function to_stream_key(d, aliases) {
    return d['ta'].replace(/:/g, '') + '---' + d['ra'].replace(/:/g, '');
}

function to_visible_stream_key(d) {
    return d.replace(/---/g, '→')
}

function to_css_stream_key(d) {
    return d.replace(/→/g, '---')
}

function replace_address_with_alias(d, aliases) {
    d['ta'] = aliases[d['ta']] || d['ta']
    d['ra'] = aliases[d['ra']] || d['ra']
}

function complement_stream_id(key) {
    // match any letter/number for aliases
    var re = /(([a-z]|[A-Z]|[0-9])+)---(([a-z]|[A-Z]|[0-9])+)/
    var z = key.match(re)
    return z[3] + "---" + z[1]
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
    var legend = d3
        .select('body')
        .append('svg')
        .attr('class', 'legend')
        .attr('width', dimensions.width.chart)
        .attr('height', dimensions.height.per_chart)
        .append("g")
        .attr("transform", "translate(" + dimensions.page.left + ",0)");

    var font_width = 6;
    var key_length = font_width * ((12 + 5) * 2 + 1);
    var total_length = key_length;
    var n_cols = Math.floor(total_width / total_length);

    for (var i in stream2packetsArray) {
        var streamId = stream2packetsArray[i];
        var count = stream2packetsDict[streamId].values.length;
        var legend_line_height = 30;
        // only show on legend if more than 1% belong to this stream
        if (count > number_of_packets * .01) {
            var col = i % n_cols;
            var row = Math.floor(i / n_cols);
            legend.append('text')
                .attr('class', 'legend stream_' + streamId + ' ta_' + streamId.split("---")[0] + ' ra_' + streamId.split("---")[1])
                .attr('x', col * total_length)
                .attr('y', (row + .5) * legend_line_height)
                .text(to_visible_stream_key(streamId))
                .on('click', function() {
                    console.log(this)
                });
        } else {
            break;
        }
    }
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
    .attr("width", sidebar_width - 10)
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
        .attr('height', dimensions.height.per_chart + dimensions.height.x_axis + dimensions.height.above_charts + dimensions.height.below_charts)
        .append("g")
        .attr("transform", "translate(" + dimensions.page.left + "," + dimensions.height.above_charts + ")");;

    if (field_settings[field].value_type == 'number') {
        visualize_numbers(field, mainChart)
    } else if (field_settings[field].value_type == 'boolean') {
        visualize_boolean(field, mainChart);
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
            return dimensions.height.per_chart
        })
        .y1(function(d) {
            if (runningSeq.length > rollingAverageLength) {
                runningCount = runningCount - runningSeq.shift();
            }
            runningSeq.push(d[currentField]);
            runningCount = runningCount + d[currentField];
            return dimensions.height.per_chart * .45 * (1 - runningCount / rollingAverageLength) + dimensions.height.per_chart * .55;
        })
        .interpolate("basis");

    return k(data)
}

function visualize_boolean(field, svg) {

    var boolean_boxes = svg.append('g').attr("class", 'boolean_boxes_' + field).attr("fill", "grey").attr("opacity", .5)

    // rectangle view 
    enter_boolean_boxes_by_dataset(field,
        boolean_boxes.selectAll('.bool_boxes_rect_' + field)
        .data(dataset, function(d) {
            return d.pcap_secs
        }));

    // area chart view
    draw_boolean_percent_chart(field, svg)

    // x and y axis
    draw_metric_x_axis(svg, field);
}

function draw_boolean_percent_chart(field, svg) {
    // area chart showing percent of last 20 that were "bad"
    svg.append("rect")
        .attr("class", "background_box")
        .attr("width", dimensions.width.chart)
        .attr("height", dimensions.height.per_chart * .45)
        .attr("x", 0)
        .attr("y", dimensions.height.per_chart * .55);

    svg.append("path")
        .attr("class", "percent_area_chart_boolean_" + field + " percent_area")
        .attr("d", boolean_percent_of_total_area_setup(dataset, field, scaled('pcap_secs')));
}

function enter_boolean_boxes_by_dataset(fieldName, svg) {
    svg.enter()
        .append('rect')
        .attr('x', scaled('pcap_secs'))
        .attr('y', function(d) {
            if (d[fieldName] == 1) {
                return 0
            } else {
                return dimensions.height.per_chart * .2
            }
        })
        .attr('width', 2)
        .attr('height', dimensions.height.per_chart * .18)
        .attr("class", function(d) {
            return 'bool_boxes_rect_' + fieldName + " " + ' ta_' + d.ta + ' ra_' + d.ra + ' stream_' + d.streamId + " " + determine_selected_class(d);
        })
}

function determine_selected_class(d) {
    if (!state.selected_data.stream || state.selected_data.stream == null) {
        return "";
    } else if (d.dsmode == 1) {
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
    // set up crosshairs element
    reticle[field] = svg.append('g')
        .attr("class", "focus")
        .style('display', null);

    // draw points
    draw_points(field, svg);

    // x and y axis
    draw_metric_x_axis(svg, field);
    draw_metric_y_axis(svg, field);

    // Add crosshairs
    draw_crosshairs(reticle[field]);

    // append the rectangle to capture mouse movements
    draw_hidden_rect_for_mouseover(svg, field)
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
            return 'points' + ' ta_' + d.ta + ' ra_' + d.ra + ' stream_' + d.streamId
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
        .attr('transform', 'translate(' + dimensions.width.chart / 2 + ',' + (dimensions.height.per_chart + dimensions.height.x_axis + dimensions.height.below_charts / 3) + ')')
        .attr("class", "text-label")
        .attr("text-anchor", "middle")
        .text(fieldName);

    // x axis
    var xaxis = svg.append('g')
        .attr('class', 'axis x metric')
        .on("dblclick", function() {
            var currentDomain = state.scales['pcap_secs'].domain();
            var zoomCenter = state.scales['pcap_secs'].invert(d3.event.x);

            var newDomain = [(zoomCenter - currentDomain[0]) / 2 + currentDomain[0], (zoomCenter - currentDomain[1]) / 2 + currentDomain[1]];

            // update brush domain and visible extent
            brush.extent(newDomain)
            d3.selectAll(".brush").call(brush)

            update_pcaps_domain(newDomain)
        })
        .attr('transform', 'translate(0,' + (dimensions.height.per_chart) + ')')

    xaxis.call(pcapSecsAxis);
    xaxis.append("rect").attr('height', dimensions.height.x_axis).attr('width', dimensions.width.chart).style('opacity', 0);

}

function update_pcaps_domain(newDomain) {
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

            points.attr('cx', scaled('pcap_secs'))

            points.enter()
                .append('circle')
                .attr('cx', scaled('pcap_secs'))
                .attr('cy', scaled(fieldName))
                .attr("class", function(d) {
                    return 'points ' + ' ta_' + d.ta + ' ra_' + d.ra + ' stream_' + d.streamId + " " + determine_selected_class(d)
                })
                .attr('r', 2);
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
            bool_boxes_current.attr('x', scaled('pcap_secs'));

            // enter
            enter_boolean_boxes_by_dataset(fieldName, bool_boxes_current)

        }

    })
}

// helper functions for update
function trim_by_pcap_secs(data) {
    // slice dataset based on desired min/max pcap milliseconds
    var domain = state.scales['pcap_secs'].domain();
    return data.slice(binary_search_by_pcap_secs(data, domain[0]), binary_search_by_pcap_secs(data, domain[1]));
}

// helper functions for selection
function draw_hidden_rect_for_mouseover(svg, fieldName) {
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
        .on('click', function() {
            d = find_packet(d3.mouse(this)[0], d3.mouse(this)[1], fieldName, false);
            if (!d) return;
            select_stream(d);
            update_crosshairs(d, fieldName);
        })
        .on('mousemove', function() {
            d = find_packet(d3.mouse(this)[0], d3.mouse(this)[1], fieldName, true);
            //      if (!state.selected_data.stream) {
            //          // do nothing
            //      }
            if (!d) return;
            update_crosshairs(d, fieldName);
        });
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

function update_crosshairs(d, field) {
    var detailedInfo = d;

    for (var r_field in reticle) {
        var closest_x = scaled('pcap_secs')(d);
        var closest_y = scaled(r_field)(d);

        reticle[r_field].select('.x')
            .attr('transform', 'translate(' + closest_x + 10 + ',0)');
        reticle[r_field].select('.y')
            .attr('transform', 'translate(0,' + closest_y + ')');

        // note - throws NaN errors when y is not a numeric value
        reticle[r_field].select('circle.y')
            .attr('transform',
                'translate(' + closest_x + ',' + closest_y + ')');
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
            return k + ": " + data[k]
        });
}

function highlight_stream(d) {
    d3.selectAll(".legend").classed("selected_downstream", false).classed("selected_upstream", false)

    // to do - limit these?
    d3.selectAll(".selected_downstream").classed("selected_downstream", false)
    d3.selectAll(".selected_upstream").classed("selected_upstream", false)
    d3.selectAll(".selected_partialMatch_downstream").classed("selected_partialMatch_downstream", false)
    d3.selectAll(".selected_partialMatch_upstream").classed("selected_partialMatch_upstream", false)

    if (d.dsmode == 1) {

        d3.selectAll(".stream_" + d.streamId).classed("selected_upstream", true)
        d3.selectAll(".stream_" + complement_stream_id(d.streamId)).classed("selected_downstream", true)
        d3.selectAll(".ta_" + d.ta).classed("selected_partialMatch_upstream", true);
        d3.selectAll(".ra_" + d.ra).classed("selected_partialMatch_upstream", true);

    } else {
        d3.selectAll(".stream_" + d.streamId).classed("selected_downstream", true)
        d3.selectAll(".stream_" + complement_stream_id(d.streamId)).classed("selected_upstream", true)
        d3.selectAll(".ta_" + d.ta).classed("selected_partialMatch_downstream", true)
        d3.selectAll(".ra_" + d.ra).classed("selected_partialMatch_downstream", true)
    }

}

function select_stream(d) {
    // if new stream selected, update view & selected stream
    if (!state.selected_data.stream || d.streamId != state.selected_data.stream) {

        // need to clear because from the legend the user can click on another stream even when a stream is "locked"
        // which is not possible from the points since you can only mouseover your state.selected_data.stream

        state.selected_data.stream = d.streamId;
        if (d.dsmode == 1) {
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
    return d3.time.format("%L")(new Date(d * 1000))
}
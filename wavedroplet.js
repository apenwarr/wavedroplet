"use strict";

var debug = false;

function log(o) {
    if (debug) {
        console.log(o);
    }
}

var w = window,
    d = document,
    e = d.documentElement,
    g = d.getElementsByTagName('body')[0];

var total_width = w.innerWidth || e.clientWidth || g.clientWidth;
var total_height = w.innerHeight || e.clientHeight || g.clientHeight;
var sidebar_width = 180;
var dim = {
    width: 0,
    height: 0,
    padding: 20
}
var tooltipLabelsHeight = 15; // height per line in detailed mouseover view
var number_of_packets;

var availableMetrics = ["antenna",
    "channel_flags",
    "dbm_antnoise",
    "dbm_antsignal",
    "dsmode",
    "duration",
    "flags",
    "frag",
    "freq",
    "incl_len",
    "mac_usecs",
    "order",
    "orig_len",
    "pcap_secs",
    "powerman",
    "ta",
    "type",
    "typestr",
    "ra",
    "rate",
    "retry",
    "seq",
    "xa"
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
    "dbm_antsignal",
    "dbm_antnoise",
    "bad"
];

// define settings per viewable metric
var field_settings = {
    'pcap_secs': {
        'parser': parseFloat,
        'scale_type': 'linear',
    },
    'seq': {
        'parser': Number,
        'scale_type': 'linear',
    },
    'rate': {
        'parser': Number,
        'scale_type': 'log',
    }
}

for (var i in selectableMetrics) {
    if (!field_settings[selectableMetrics[i]]) {
        field_settings[selectableMetrics[i]] = {
            'parser': parseFloat,
            'scale_type': 'linear'
        }
    }
}

// global variables
var state = {
    to_plot: [],
    scales: [],
    // When not null, crosshairs will focus only on packets for this stream.
    selected_stream: null
}
var reticle = {}; // dict[field; crosshair]
var histogramPacketNum = [] // array to be used to create overview histogram

var pcapSecsAxis = d3.svg.axis()
    .tickFormat(hourMinuteMilliseconds)
    .orient('bottom')
    .ticks(5);

var dataset; // all packets, sorted by pcap_secs
var stream2packetsDict = {};
var stream2packetsArray = [];


// get data & visualize
d3.json('/json/' + get_query_param('key')[0], function(error, json) {
    if (error) return console.error('error');

    var begin = new Date().getTime();

    init(json);
    draw();

    var end = new Date().getTime();
    log('Spent on visualization ' + ((end - begin) / 1000) + ' sec.');
})

function get_query_param(param) {
    var urlKeyValuePairs = {}
    window.location.search.split("?")[1].split("&").forEach(function(d) {
        var m = d.split("=");
        urlKeyValuePairs[m[0]] = m[1]
    })
    return urlKeyValuePairs[param].split(',')
}

function to_stream_key(d) {
    return d['ta'].replace(/:/g, '') + '_' + d['ra'].replace(/:/g, '');
}

// there must be a beter way... 
function from_stream_key(key) {
    var z = key.split('_')
    var ta = z[0].slice(0, 2) + ':' + z[0].slice(2, 4) +
        ':' + z[0].slice(4, 6) +
        ':' + z[0].slice(6, 8) +
        ':' + z[0].slice(8, 10) +
        ':' + z[0].slice(10, 12);
    var ra = z[1].slice(0, 2) + ':' + z[1].slice(2, 4) +
        ':' + z[1].slice(4, 6) +
        ':' + z[1].slice(6, 8) +
        ':' + z[1].slice(8, 10) +
        ':' + z[1].slice(10, 12);
    return {
        'ta': ta,
        'ra': ra
    };
}

function complement_stream_id(key) {
    var re = /(([a-f]|[0-9])+)_(([a-f]|[0-9])+)/
    var z = key.match(re)
    return z[3] + "_" + z[1]
}

function init(json) {
    // TODO(katepek): Should sanitize here? E.g., discard bad packets?
    // Packets w/o seq?
    dataset = JSON.parse(json.js_packets);

    state.to_plot = get_query_param('to_plot');

    // Leave only packets that have all the fields that we want to plot
    sanitize_dataset();

    dataset.sort(function(x, y) {
        return x['pcap_secs'] - y['pcap_secs'];
    });

    // TODO(katepek): Recalculate and redraw when resized
    dim.height = (total_height - 3 * state.to_plot.length * dim.padding) / state.to_plot.length;
    dim.width = total_width - 4 * dim.padding - sidebar_width;

    var x_range = [dim.padding, dim.width - 3 * dim.padding];
    var y_range = [dim.height - 1.5 * dim.padding, 1.5 * dim.padding];

    log('total_height = ' + total_height);
    log('height = ' + dim.height);

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
        // store time of packet
        packetSecs.push(d.pcap_secs)

        // track streams
        var streamId = to_stream_key(d);
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


function sanitize_dataset() {
    log('Before filtering: ' + dataset.length);
    dataset = dataset.filter(function(d) {
        if (!d['pcap_secs']) return false;
        if (d['pcap_secs'] <= 0) return false;

        if (!d['ta'] || !d['ra'])
            return false;

        for (var idx in state.to_plot) {
            if (!d.hasOwnProperty(state.to_plot[idx])) return false;
        }
        return true;
    });
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

function scaled(name) {
    return function(d) {
        return state.scales[name](d[name]);
    }
}

function draw() {
    add_butter_bar();

    add_overview();

    state.to_plot.forEach(function(d) {
        visualize(d, dim)
    })

    add_legend();
}

function add_overview() {
    var histHeight = 80;
    var max = 0;

    // find max bar height and use to set Y axis for overview chart
    histogramPacketNum.forEach(function(d) {
        if (d.y > max) {
            max = d.y;
        }
    })
    state.scales["packetNumPerTenth"] = d3.scale.linear().domain([0, max]).range([histHeight, 0])

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
    var svg = d3
        .select('body')
        .append('svg')
        .attr('id', 'histogramZoomNav')
        .attr('width', dim.width)
        .attr('height', histHeight + 20);

    // append x-axis
    svg.append('g')
        .attr('class', 'axis x overview')
        .attr('transform', 'translate(0,' + histHeight + ')')
        .call(overviewXaxis);

    svg.append('g')
        .attr('class', 'axis y overview')
        .attr('transform', 'translate(' + (dim.width - 3 * dim.padding) + ', 0)')
        .call(overviewYaxis);

    // draw bars
    svg.selectAll(".histBar")
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
            return histHeight - state.scales["packetNumPerTenth"](d.y)
        });

    // set up brush
    var brush = d3.svg.brush()
        .x(state.scales['pcap_secs_fixed'])
        .on("brush", brushed);

    svg.append("g")
        .attr("class", "x brush")
        .call(brush)
        .selectAll("rect")
        .attr("y", -6)
        .attr("height", histHeight + 7);

    // on brush, zoom/pan rest of charts
    function brushed() {
        state.scales['pcap_secs'].domain(brush.empty() ? state.scales['pcap_secs_fixed'].domain() : brush.extent());
        d3.selectAll(".axis.x.metric").call(pcapSecsAxis);
        d3.selectAll(".points").attr('cx', scaled('pcap_secs'))
    }
}

function add_butter_bar() {
    var svg = d3
        .select('body')
        .append('svg')
        .attr('id', 'butter_bar')
        .attr('width', dim.width)
        .attr('height', dim.padding);
    svg.append('rect')
        .attr('id', 'butter_bar_box')
        .attr('width', dim.width)
        .attr('height', dim.padding)
        .style('fill', 'none');
    svg.append('text')
        .attr('id', 'butter_bar_msg')
        .attr('class', 'legend')
        .attr('x', dim.width / 2 - 4 * dim.padding)
        .attr('y', 2 + dim.padding / 2)
        .style('fill', 'black')
        .style('font-size', 14);
}

function add_legend() {
    var svg = d3
        .select('body')
        .append('svg')
        .attr('class', 'legend')
        .attr('width', dim.width)
        .attr('height', dim.height);

    var font_width = 6;
    var key_length = font_width * ((12 + 5) * 2 + 1);
    var total_length = key_length + 4.5 * dim.padding;
    var n_cols = Math.floor(total_width / total_length);

    for (var i in stream2packetsArray) {
        var streamId = stream2packetsArray[i];
        var count = stream2packetsDict[streamId].values.length;
        // only show on legend if more than 1% belong to this stream
        if (count > number_of_packets * .01) {
            var col = i % n_cols;
            var row = Math.floor(i / n_cols);
            svg.append('text')
                .attr('class', 'legend stream_' + streamId)
                .attr('x', col * total_length + 2 * dim.padding)
                .attr('y', (row + 1.5) * dim.padding)
                .text(streamId)
                .on('click', function() {
                    select_stream(this.textContent);
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
    .style('top', (2 * dim.padding) + 'px')
    .classed('hidden', true)
    .append("svg")
    .attr("width", 200)
    .attr("height", availableMetrics.length * tooltipLabelsHeight)
    .selectAll('.tooltipValues')
    .data(availableMetrics)
    .enter()
    .append("text")
    .attr("class", "tooltipValues")
    .attr("y", function(k, i) {
        return i * tooltipLabelsHeight + 10
    });

function visualize(field, dim) {
    log('About to visualize ' + field);

    // set up main svg for plot
    var svg = d3.select('body')
        .append('svg')
        .attr('class', 'plot_' + field)
        .attr('width', dim.width)
        .attr('height', dim.height);

    // set up crosshairs element
    reticle[field] = svg.append('g')
        .attr("class", "focus")
        .style('display', null);

    // draw points
    stream2packetsArray.forEach(function(d) {
        draw_points_per_stream(field, d, stream2packetsDict, svg)
    });

    // x and y axis
    draw_metric_axes(svg, field, dim);

    // Add crosshairs
    draw_crosshairs(reticle[field]);

    // append the rectangle to capture mouse movements
    draw_hidden_rect_for_mouseover(svg, field)
}

// visualization set up functions
function draw_points_per_stream(fieldName, streamId, packetsDictionary, svg) {
    svg.append('g').attr("class", 'pcap_vs_' + fieldName + " stream_" + streamId + " metricChart").attr("fill", 'grey')
        .selectAll('.points')
        .data(packetsDictionary[streamId].values)
        .enter()
        .append('circle')
        .attr('class', 'points')
        .attr('cx', scaled('pcap_secs'))
        .attr('cy', scaled(fieldName))
        .attr('r', 2);
}

function draw_metric_axes(svg, fieldName, dim) {
    var yAxis = d3.svg.axis()
        .scale(state.scales[fieldName])
        .orient('right')
        .ticks(5);

    svg.append('g')
        .attr('class', 'axis x metric')
        .attr('transform', 'translate(0,' + (dim.height - 1.5 * dim.padding) + ')')
        .call(pcapSecsAxis);
    svg.append('g')
        .attr('class', 'axis y')
        .attr('transform', 'translate(' + (dim.width - 3 * dim.padding) + ',0)')
        .call(yAxis);
}

function draw_hidden_rect_for_mouseover(svg, fieldName) {
    svg.append('rect')
        .attr('width', dim.width)
        .attr('height', dim.height)
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
            d = find_packet(d3.mouse(this)[0], d3.mouse(this)[1], fieldName);
            if (!d) return;
            select_stream(to_stream_key(d));
            update_crosshairs(d, fieldName);
        })
        .on('mousemove', function() {
            d = find_packet(d3.mouse(this)[0], d3.mouse(this)[1], fieldName);
            if (!d) return;
            update_crosshairs(d, fieldName);
        });
}

function draw_crosshairs(element) {
    element.append('line')
        .attr('class', 'x')
        .attr('y1', 0)
        .attr('y2', dim.height);

    element.append('line')
        .attr('class', 'y')
        .attr('x1', 0)
        .attr('x2', dim.width);

    element.append('circle')
        .attr('class', 'y')
        .attr('r', 7);

    element.append('text')
        .attr('class', 'y1')
        .attr('dx', 8)
        .attr('dy', '-.5em');
}


function binary_search_by(field) {
    return d3.bisector(function(d) {
        return d[field]
    }).left;
}

function find_packet(x, y, field) {
    if (x < state.scales['pcap_secs'].range()[0] ||
        x > state.scales['pcap_secs'].range()[1] ||
        y > total_height)
        return;

    var pcap_secs = state.scales['pcap_secs'].invert(x);
    var search_in = dataset;

    if (state.selected_stream) {
        search_in = stream2packetsDict[state.selected_stream].values;
    }

    var idx = binary_search_by('pcap_secs')(search_in, pcap_secs, 0);
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
            return k + ": " + data[k]
        });
}

function select_stream(streamId) {

    // if new stream selected, update view & selected stream
    if (!state.selected_stream || streamId != state.selected_stream) {

        // need to clear because from the legend the user can click on another stream even when a stream is "locked"
        // which is not possible from the points since you can only mouseover your state.selected_stream
        d3.selectAll(".legend").classed("selected", false).classed("selectedComplement", false)

        state.to_plot.forEach(function(d) {
            d3.selectAll(".pcap_secs_vs" + state.to_plot).classed("selected", false).classed("selectedComplement", false)
        })

        // select these points
        d3.selectAll('.stream_' + streamId)
            .classed("selected", true)
            .classed("selectedComplement", false);

        d3.selectAll('.stream_' + complement_stream_id(streamId))
            .classed("selectedComplement", true)
            .classed("selected", false);

        state.selected_stream = streamId;
        butter_bar('Locked to: ' + streamId)
    } else {
        d3.selectAll(".selected").classed("selected", false);
        d3.selectAll(".selectedComplement").classed("selectedComplement", false);
        state.selected_stream = null;
        butter_bar('Unlocked')
    }
}

// time formatting functions
function hourMinuteMilliseconds(d) {
    return d3.time.format("%H:%M:%S")(new Date(d * 1000))
}

function milliseconds(d) {
    return d3.time.format("%L")(new Date(d * 1000))
}
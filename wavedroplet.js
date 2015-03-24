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
var width; // of a plot
var height; // of a plot
var padding = 20;
var tooltipLabelsHeight = 15; // height per line in detailed mouseover view

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

var to_plot = []; // fields to be plotted against X axis (time)
var scales = {}; // dict[field; scale], incl. X axis
var reticle = {}; // dict[field; crosshair]

var dataset; // all packets, sorted by pcap_secs
var streams; // streams: pairs of (transmitter, receiver)
// dataset split by streams as a list of key-value pairs (key ='ta-ra')
// sorted descending by the number of packets belonging to each stream
var stream2packetsDict = {};
var stream2packetsArray = [];

// When not null, crosshairs will focus only on packets for this stream.
var selected_stream = null; // one of the key-value pairs of stream2packets

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
    streams = JSON.parse(json.js_streams);

    to_plot = get_query_param('to_plot');

    // Leave only packets that have all the fields that we want to plot
    sanitize_dataset();

    dataset.sort(function(x, y) {
        return x['pcap_secs'] - y['pcap_secs'];
    });

    dataset.forEach(function(d) {
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

    stream2packetsArray.sort(function(a, b) {
        return stream2packetsDict[b].values.length - stream2packetsDict[a].values.length
    })

    // TODO(katepek): Recalculate and redraw when resized
    height = (total_height - 3 * to_plot.length * padding) / to_plot.length;
    width = total_width - 4 * padding - sidebar_width;

    var x_range = [padding, width - 3 * padding];
    var y_range = [height - 1.5 * padding, 1.5 * padding];

    log('total_height = ' + total_height);
    log('height = ' + height);

    add_scale('pcap_secs', x_range);
    to_plot.forEach(function(d) {
        add_scale(d, y_range)
    });
}


function sanitize_dataset() {
    log('Before filtering: ' + dataset.length);
    dataset = dataset.filter(function(d) {
        if (!d['pcap_secs']) return false;
        if (d['pcap_secs'] <= 0) return false;

        if (!d['ta'] || !d['ra'])
            return false;

        for (var idx in to_plot) {
            if (!d.hasOwnProperty(to_plot[idx])) return false;
        }
        return true;
    });
    log('After filtering: ' + dataset.length);
}

function add_scale(field, range) {
    scales[field] = d3.scale[field_settings[field]['scale_type']]()
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
        return scales[name](d[name]);
    }
}

function draw() {
    add_butter_bar();

    to_plot.forEach(function(d) {
        visualize(d)
    })

    add_legend();
}

function add_butter_bar() {
    var svg = d3
        .select('body')
        .append('svg')
        .attr('id', 'butter_bar')
        .attr('width', width)
        .attr('height', padding);
    svg.append('rect')
        .attr('id', 'butter_bar_box')
        .attr('width', width)
        .attr('height', padding)
        .style('fill', 'none');
    svg.append('text')
        .attr('id', 'butter_bar_msg')
        .attr('class', 'legend')
        .attr('x', width / 2 - 4 * padding)
        .attr('y', 2 + padding / 2)
        .style('fill', 'black')
        .style('font-size', 14);
}

function add_legend() {
    var svg = d3
        .select('body')
        .append('svg')
        .attr('class', 'legend')
        .attr('width', width)
        .attr('height', height);

    var font_width = 6;
    var key_length = font_width * ((12 + 5) * 2 + 1);
    var total_length = key_length + 4.5 * padding;
    var n_cols = Math.floor(total_width / total_length);

    for (var i in stream2packetsArray) {
        var streamId = stream2packetsArray[i];
        var count = stream2packetsDict[streamId].values.length;
        // only show on legend if more than 50 packets belong to this stream
        if (count > 50) {
            var col = i % n_cols;
            var row = Math.floor(i / n_cols);
            svg.append('text')
                .attr('class', 'legend legend_' + streamId)
                .attr('x', col * total_length + 2 * padding)
                .attr('y', (row + 1.5) * padding)
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
        .duration(1500)
        .style('opacity', 0);
    d3.select('rect#butter_bar_box')
        .transition()
        .duration(500)
        .style('opacity', 0);
}


var details = d3.select('#tooltip')
    .style('top', (2 * padding) + 'px')
    .classed('hidden', true)
    .append("svg")
    .attr("width", 200)
    .attr("height", availableMetrics.length * tooltipLabelsHeight);

function visualize(field) {
    log('About to visualize ' + field);

    var svg = d3
        .select('body')
        .append('svg')
        .attr('class', 'plot_' + field)
        .attr('width', width)
        .attr('height', height);

    var focus = svg.append('g')
        .attr("class", "focus")
        .style('display', null);

    reticle[field] = focus;

    stream2packetsArray.forEach(function(d, i) {
        var current_plot_id = 'pcap_vs_' + field + '_' + d;

        svg.append('g').attr("class", current_plot_id).attr("fill", 'grey')
            .selectAll('.points')
            .data(stream2packetsDict[d].values)
            .enter()
            .append('circle')
            .attr('class', 'points')
            .attr('cx', scaled('pcap_secs'))
            .attr('cy', scaled(field))
            .attr('r', 2);
    });

    var pcapSecsAxis = d3.svg.axis()
        .scale(scales['pcap_secs'])
        .tickFormat(hourMinuteMilliseconds)
        .orient('bottom')
        .ticks(5);

    var yAxis = d3.svg.axis()
        .scale(scales[field])
        .orient('right')
        .ticks(5);


    // set up zoom
    var zoom = d3.behavior.zoom().x(scales['pcap_secs']).on("zoom", showZoom);

    function showZoom(d) {
            d3.selectAll(".axis.x").call(pcapSecsAxis);
            d3.selectAll(".points").attr('cx', scaled('pcap_secs'))
        }
        // end zooming

    svg.append('g')
        .attr('class', 'axis x')
        .attr('transform', 'translate(0,' + (height - 1.5 * padding) + ')')
        .call(pcapSecsAxis);
    svg.append('g')
        .attr('class', 'axis y')
        .attr('transform', 'translate(' + (width - 3 * padding) + ',0)')
        .call(yAxis);

    // Add crosshairs
    focus.append('line')
        .attr('class', 'x')
        .attr('y1', 0)
        .attr('y2', height);

    focus.append('line')
        .attr('class', 'y')
        .attr('x1', 0)
        .attr('x2', width);

    focus.append('circle')
        .attr('class', 'y')
        .attr('r', 7);

    focus.append('text')
        .attr('class', 'y1')
        .attr('dx', 8)
        .attr('dy', '-.5em');

    // append the rectangle to capture mouse movements
    svg.append('rect')
        .attr('width', width)
        .attr('height', height)
        .attr("class", "plotRect")
        .style('fill', 'none')
        .style('pointer-events', 'all')
        .call(zoom)
        .on('mouseover', function() {
            for (var i in Object.keys(reticle)) {
                var current = reticle[Object.keys(reticle)[i]];
                current.style('display', null);
                current.select('.y').style('display', null);
                current.select('circle.y').style('display', null);
                current.select('text.y1').style('display', null);
            }
        })
        .on('mouseout', function() {
            var x = d3.mouse(this)[0];
            if (x < scales['pcap_secs'].range()[0] ||
                x > scales['pcap_secs'].range()[1]) {
                d3.select('#tooltip').classed("hidden", true)
                for (var i in Object.keys(reticle)) {
                    reticle[Object.keys(reticle)[i]].style('display', 'none');
                }
            }
        })
        .on('click', function() {
            d = find_packet(d3.mouse(this)[0], d3.mouse(this)[1], field);
            if (!d) return;
            select_stream(to_stream_key(d));
            draw_crosshairs(d, field);
        })
        .on('mousemove', function() {
            d = find_packet(d3.mouse(this)[0], d3.mouse(this)[1], field);
            if (!d) return;
            draw_crosshairs(d, field);
        });
}

function binary_search_by(field) {
    return d3.bisector(function(d) {
        return d[field]
    }).left;
}

function find_packet(x, y, field) {
    if (x < scales['pcap_secs'].range()[0] ||
        x > scales['pcap_secs'].range()[1] ||
        y > total_height)
        return;

    var pcap_secs = scales['pcap_secs'].invert(x);
    var search_in = dataset;

    if (selected_stream) {
        search_in = stream2packetsDict[selected_stream].values;
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

function draw_crosshairs(d, field) {
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

    d3.select('#tooltip')
        .classed('hidden', false).select("svg")
        .selectAll('.tooltipValues')
        .data(availableMetrics)
        .enter()
        .append("text")
        .attr("class", "tooltipValues")
        .attr("y", function(k, i) {
            return i * tooltipLabelsHeight + 10
        })
        .text(function(k) {
            return k + ": " + detailedInfo[availableMetrics]
        });

    d3.selectAll(".tooltipValues")
        .data(availableMetrics)
        .text(function(k) {
            return k + ": " + detailedInfo[k]
        });

}

function select_stream(streamId) {

    // if new stream selected, update view & selected stream
    if (!selected_stream || streamId != selected_stream) {
        // select current legend
        d3.select('.legend_' + streamId).classed("selected", true).classed("selectedComplement", false);
        d3.select('.legend_' + complement_stream_id(streamId)).classed("selectedComplement", true).classed("selected", false);
        // select these points
        for (var idx in to_plot) {

            d3.selectAll('.pcap_vs_' + to_plot[idx] + '_' + streamId)
                .classed("selected", true)
                .classed("selectedComplement", false);

            d3.selectAll('.pcap_vs_' + to_plot[idx] + '_' + complement_stream_id(streamId))
                .classed("selectedComplement", true)
                .classed("selected", false);
        }

        selected_stream = streamId;
        butter_bar('Locked to: ' + streamId)
    } else {
        d3.selectAll(".selected").classed("selected", false);
        d3.selectAll(".selectedComplement").classed("selectedComplement", false);
        selected_stream = null;
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
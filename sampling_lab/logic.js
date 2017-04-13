var g_input
var g_output
var g_canvas

/******************************************************************************
 * debug
 *****************************************************************************/
var g_DEBUG = 1

function debug(msg) {
    if(g_DEBUG) {
        console.log(msg)
    }
}

/******************************************************************************
 * HELPERS
 *****************************************************************************/

/* parses the lines of an element, splitting on tab
	returns array of records
	where record is {'value':<number>, 'line':<line>} */
function recordsFromElem(elem)
{
	valueCol = parseInt(document.getElementById('valueColumn').value)

	var result = []
	var lines = elem.value.split("\n")
	for(var i=0; i<lines.length; ++i) {
		var fields = lines[i].split("\t")
		var record = {}

		var valStr = fields[valueCol-1]
		m = valStr.match(/^-?\$?([\d,]+\.?\d{1,2})$/)
		if(!m) {
			alert("ERROR: " + valStr + " doesn't look like a value")
			return null;
		}	
		valStr = m[1]
		valStr = valStr.replace(/,/g, '')
		var value = Math.abs(parseFloat(valStr))

		record['value'] = Math.abs(parseFloat(valStr))
		record['line'] = lines[i]
		result.push(record)
	}
	return result
}


/* input: array of records
 where record is {'value':<number>, 'line':<line>} */
function recordsToElem(records, elem)
{
	var dataStr = ''

	for(var i=0; i<records.length; ++i) {
		dataStr += records[i]['line']

		if(i != records.length-1) {
			dataStr += '\n';
		}
	}

	elem.value = dataStr
}

/******************************************************************************
 * SERVICE ROUTINES
 *****************************************************************************/

function doClear() {
	g_input.innerText = ''
	g_output.innerText = ''
	g_canvas.width = 1
	g_canvas.height = 1
}

function doSampling() {
	var records = recordsFromElem(g_input);
	if(records == null) return
	var weight = document.getElementById('weight').value
	var sampSize = document.getElementById('sampSize').value
	var useMateriality = document.getElementById('useMateriality').value
	var materiality = parseFloat(document.getElementById('materiality').value)

	/* sanity check */
	if(sampSize > records.length) {
		alert("ERROR: you can't sample " + sampSize + 
			" records from a pool of " + records.length)
		return;
	}

	/* create ticket intervals for all values */
	var cur = 0
	var pool = []
	for(var i=0; i<records.length; ++i) {
		var value = records[i]['value']
		var ticketLo = cur
		var ticketHi
		if(weight == 'fair')
			ticketHi = ticketLo+1
		else
		if(weight == 'medium')
			ticketHi = ticketLo + (1 + .10*value)
		else
		if(weight == 'mut')
			ticketHi = ticketLo + value

		var entry = {}
		entry['value'] = value
		entry['line'] = records[i]['line']
		entry['ticketLo'] = ticketLo
		entry['ticketHi'] = ticketHi
		pool.push(entry)

		cur = ticketHi
	}

	var winners = []
	var losers = []

	/* if materiality specified, values >= materiality automatically win */
	if(useMateriality == 'on') {
		for(var i=0; i<pool.length; ++i) {
			if(pool[i]['value'] >= materiality)
				winners.push(pool[i])

			if(winners.length >= sampSize)
				break;
		}
	}

	/* draw winners */
	while(pool.length) {
		var ticket = Math.random() * pool[pool.length-1]['ticketHi']

		/* find winner */
		var drawIdx = -1
		var minIdx = 0
		var maxIdx = pool.length-1

		while(minIdx <= maxIdx) {
			var curIdx = Math.floor((minIdx + maxIdx)/2)
			var left = pool[curIdx]['ticketLo']
			var right = pool[curIdx]['ticketHi']
			
			if(ticket < left) {
				maxIdx = curIdx - 1;
			}
			else
			if(ticket >= right) {
				minIdx = curIdx + 1;
			}
			else {
				drawIdx = curIdx
				break
			}
		}

		if(drawIdx == -1) {
			alert("MAJOR ERROR! BLAME DEVELOPER!")
		}

		if(winners.length < sampSize)
			winners.push(pool[drawIdx])
		else
			losers.push(pool[drawIdx])

		/* collapse all indices following the winner */
		var curEnd = pool[drawIdx]['ticketLo']
		for(var j=drawIdx+1; j<pool.length; ++j) {
			var length = pool[j]['ticketHi'] - pool[j]['ticketLo']
			pool[j]['ticketLo'] = curEnd
			pool[j]['ticketHi'] = curEnd + length;
			curEnd = pool[j]['ticketHi']
		}

		/* delete winner from pool */
		pool.splice(drawIdx, 1)
	}

	/* use winners list to update output text */
	recordsToElem(winners, g_output);

	/* draw this shit */
	var maxValue = 0
	for(var i=0; i<records.length; ++i)
		maxValue = Math.max(maxValue, records[i]['value'])

	var scaler = 100 / maxValue

	g_canvas.width = Math.max(640, winners.length + losers.length)
	
	var ctx = g_canvas.getContext("2d");

	ctx.beginPath()
	ctx.rect(0, 0, g_canvas.width, g_canvas.height)
	ctx.fillStyle = "black"
	ctx.fill()

	ctx.strokeStyle="#00FF00"
	for(var i=0; i<winners.length; ++i) {
		ctx.beginPath()
		ctx.moveTo(i, 100)
		var height = scaler * winners[i]['value']
		ctx.lineTo(i, 100-height)
		ctx.stroke()
	}

	ctx.strokeStyle="#FF0000"
	for(var i=0; i<losers.length; ++i) {
		ctx.beginPath()
		ctx.moveTo(winners.length + i, 100)
		var height = scaler * losers[i]['value']
		ctx.lineTo(winners.length + i, 100-height)
		ctx.stroke()
	}
}

function logicInit() {
	/* set globals */
	g_input = document.getElementById('input')
	g_output = document.getElementById('output')
	g_canvas = document.getElementById('mycanvas')

	/* load up initial data */
	recordsToElem(g_seedData, g_input);

	/* done */
	debug("shellInit() finished")
}



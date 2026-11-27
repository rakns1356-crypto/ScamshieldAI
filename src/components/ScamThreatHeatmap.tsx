import { useEffect, useMemo, useRef, useState } from 'react';
import * as d3 from 'd3';
import { AnimatePresence, motion } from 'motion/react';
import {
  AlertTriangle,
  Compass,
  Loader2,
  MapPin,
  Radar,
  ShieldAlert,
  TrendingUp,
  ZoomIn,
  ZoomOut,
  RotateCcw,
} from 'lucide-react';
import type { ScanChannel, ScanResult } from '../types/scam';
import { postJson } from '../utils/apiClient';
import {
  REGIONAL_CELLS,
  REGIONAL_HOTSPOTS,
  REGIONS,
  SCAM_TYPES,
  WORLD_REGIONS_GEOJSON,
  detectUserRegionFromTimezone,
  type RegionId,
  type RegionalScamCell,
  type ScamTypeId,
} from '../data/threatHeatmapData';

interface ScamThreatHeatmapProps {
  userHistory: ScanResult[];
  onTestInScanner: (channel: ScanChannel) => void;
}

interface LocalAdvisoryResponse {
  summary: string;
  localSigns: string[];
  whereToReport: string;
}

interface HoverTooltipState {
  x: number;
  y: number;
  title: string;
  subtitle: string;
  intensity: number;
  deltaPct: number;
  channel?: string;
}

export function ScamThreatHeatmap({
  userHistory,
  onTestInScanner,
}: ScamThreatHeatmapProps) {
  const [userRegion, setUserRegion] = useState<RegionId>(() => detectUserRegionFromTimezone());
  const [selectedScam, setSelectedScam] = useState<ScamTypeId>('delivery-sms');
  const [mapFilter, setMapFilter] = useState<'all' | ScamTypeId>('all');
  const [timeWindow, setTimeWindow] = useState<'7d' | '30d'>('7d');
  const [viewMode, setViewMode] = useState<'both' | 'matrix' | 'map'>('both');
  const [tooltip, setTooltip] = useState<HoverTooltipState | null>(null);

  const [advisory, setAdvisory] = useState<LocalAdvisoryResponse | null>(null);
  const [advisoryLoading, setAdvisoryLoading] = useState(false);
  const [advisoryError, setAdvisoryError] = useState<string | null>(null);

  const matrixSvgRef = useRef<SVGSVGElement | null>(null);
  const mapSvgRef = useRef<SVGSVGElement | null>(null);
  const zoomBehaviorRef = useRef<d3.ZoomBehavior<SVGSVGElement, unknown> | null>(null);

  const getIntensity = (cell: RegionalScamCell) =>
    timeWindow === '7d' ? cell.intensity7d : cell.intensity30d;

  const selectedCell = useMemo(() => {
    return (
      REGIONAL_CELLS.find(
        (c) => c.regionId === userRegion && c.scamTypeId === selectedScam
      ) || REGIONAL_CELLS[0]
    );
  }, [userRegion, selectedScam]);

  const activeRegionInfo = useMemo(
    () => REGIONS.find((r) => r.id === userRegion) || REGIONS[0],
    [userRegion]
  );

  const activeScamInfo = useMemo(
    () => SCAM_TYPES.find((s) => s.id === selectedScam) || SCAM_TYPES[0],
    [selectedScam]
  );

  // Top trending threats specifically for the user's localized region
  const localTopThreats = useMemo(() => {
    return REGIONAL_CELLS.filter((c) => c.regionId === userRegion)
      .sort((a, b) => getIntensity(b) - getIntensity(a))
      .slice(0, 3)
      .map((cell) => ({
        cell,
        scam: SCAM_TYPES.find((s) => s.id === cell.scamTypeId)!,
      }));
  }, [userRegion, timeWindow]);

  // Check if the user's own personal scans match regional trends
  const matchingPersonalScanCount = useMemo(() => {
    const labelLower = activeScamInfo.label.toLowerCase();
    return userHistory.filter(
      (h) =>
        h.riskLevel !== 'Low' &&
        (h.scamCategory.toLowerCase().includes(labelLower.split(' ')[0]) ||
          h.headline.toLowerCase().includes(labelLower.split(' ')[0]))
    ).length;
  }, [userHistory, activeScamInfo]);

  // Reset AI local advisory when selection changes
  useEffect(() => {
    setAdvisory(null);
    setAdvisoryError(null);
  }, [userRegion, selectedScam]);

  const handleFetchLocalAdvisory = async () => {
    setAdvisoryLoading(true);
    setAdvisoryError(null);
    try {
      const data = await postJson<LocalAdvisoryResponse>('/api/threats/advisory', {
        regionName: activeRegionInfo.name,
        scamLabel: activeScamInfo.label,
        localExample: selectedCell.localExample,
      });
      setAdvisory(data);
    } catch (err) {
      setAdvisoryError(
        err instanceof Error ? err.message : 'Unable to fetch local advisory right now.'
      );
    } finally {
      setAdvisoryLoading(false);
    }
  };

  // --- D3 Matrix Heatmap Rendering ---
  useEffect(() => {
    if (viewMode === 'map' || !matrixSvgRef.current) return;

    const svgEl = matrixSvgRef.current;
    const svg = d3.select(svgEl);
    svg.selectAll('*').remove();

    const width = 660;
    const height = 390;
    const margin = { top: 64, right: 20, bottom: 58, left: 132 };
    const innerWidth = width - margin.left - margin.right;
    const innerHeight = height - margin.top - margin.bottom;

    svg.attr('viewBox', `0 0 ${width} ${height}`);

    const g = svg
      .append('g')
      .attr('transform', `translate(${margin.left},${margin.top})`);

    const regionIds = REGIONS.map((r) => r.id);
    const scamIds = SCAM_TYPES.map((s) => s.id);

    const xScale = d3
      .scaleBand<ScamTypeId>()
      .domain(scamIds)
      .range([0, innerWidth])
      .padding(0.1);

    const yScale = d3
      .scaleBand<RegionId>()
      .domain(regionIds)
      .range([0, innerHeight])
      .padding(0.14);

    const colorScale = d3
      .scaleSequential(d3.interpolateYlOrRd)
      .domain([25, 100]);

    // Column Headers (Scam Types)
    const xLabels = g
      .selectAll('.x-label')
      .data(SCAM_TYPES)
      .enter()
      .append('g')
      .attr('class', 'x-label')
      .attr(
        'transform',
        (d) => `translate(${(xScale(d.id) || 0) + xScale.bandwidth() / 2}, -14)`
      )
      .style('cursor', 'pointer')
      .on('click', (_event, d) => {
        setSelectedScam(d.id);
        setMapFilter(d.id);
      });

    xLabels
      .append('text')
      .attr('text-anchor', 'middle')
      .attr('font-size', '11px')
      .attr('font-weight', (d) => (d.id === selectedScam ? '700' : '600'))
      .attr('fill', (d) => (d.id === selectedScam ? '#1d4ed8' : '#334155'))
      .text((d) => d.shortLabel);

    // Row Headers (Regions, with active local region highlight)
    const yLabels = g
      .selectAll('.y-label')
      .data(REGIONS)
      .enter()
      .append('g')
      .attr('class', 'y-label')
      .attr(
        'transform',
        (d) => `translate(-12, ${(yScale(d.id) || 0) + yScale.bandwidth() / 2})`
      )
      .style('cursor', 'pointer')
      .on('click', (_event, d) => setUserRegion(d.id));

    yLabels
      .append('text')
      .attr('text-anchor', 'end')
      .attr('dominant-baseline', 'middle')
      .attr('font-size', '11.5px')
      .attr('font-weight', (d) => (d.id === userRegion ? '700' : '500'))
      .attr('fill', (d) => (d.id === userRegion ? '#1d4ed8' : '#334155'))
      .text((d) => (d.id === userRegion ? `★ ${d.shortName}` : d.shortName));

    // Active local row subtle band highlight
    const activeRowY = yScale(userRegion);
    if (activeRowY !== undefined) {
      g.append('rect')
        .attr('x', -6)
        .attr('y', activeRowY - 3)
        .attr('width', innerWidth + 12)
        .attr('height', yScale.bandwidth() + 6)
        .attr('rx', 8)
        .attr('fill', 'none')
        .attr('stroke', '#1d4ed8')
        .attr('stroke-width', 1.5)
        .attr('stroke-dasharray', '4 3')
        .attr('pointer-events', 'none');
    }

    // Heatmap Cells
    const cellGroups = g
      .selectAll('.heat-cell')
      .data(REGIONAL_CELLS)
      .enter()
      .append('g')
      .attr('class', 'heat-cell')
      .style('cursor', 'pointer')
      .on('mouseenter', function (event, d) {
        const reg = REGIONS.find((r) => r.id === d.regionId);
        const scam = SCAM_TYPES.find((s) => s.id === d.scamTypeId);
        d3.select(this)
          .select('rect')
          .attr('stroke', '#0f172a')
          .attr('stroke-width', 2);

        setTooltip({
          x: event.clientX,
          y: event.clientY,
          title: `${reg?.name || d.regionId} — ${scam?.label || d.scamTypeId}`,
          subtitle: `Primary channel: ${d.primaryChannel}`,
          intensity: getIntensity(d),
          deltaPct: d.weeklyDeltaPct,
          channel: d.primaryChannel,
        });
      })
      .on('mousemove', (event) => {
        setTooltip((prev) =>
          prev ? { ...prev, x: event.clientX, y: event.clientY } : null
        );
      })
      .on('mouseleave', function (_event, d) {
        const isSelected =
          d.regionId === userRegion && d.scamTypeId === selectedScam;
        d3.select(this)
          .select('rect')
          .attr('stroke', isSelected ? '#0f172a' : '#e2e8f0')
          .attr('stroke-width', isSelected ? 2.5 : 1);
        setTooltip(null);
      })
      .on('click', (_event, d) => {
        setUserRegion(d.regionId);
        setSelectedScam(d.scamTypeId);
      });

    cellGroups
      .append('rect')
      .attr('x', (d) => xScale(d.scamTypeId) || 0)
      .attr('y', (d) => yScale(d.regionId) || 0)
      .attr('width', xScale.bandwidth())
      .attr('height', yScale.bandwidth())
      .attr('rx', 6)
      .attr('fill', (d) => colorScale(getIntensity(d)))
      .attr('stroke', (d) =>
        d.regionId === userRegion && d.scamTypeId === selectedScam
          ? '#0f172a'
          : '#e2e8f0'
      )
      .attr('stroke-width', (d) =>
        d.regionId === userRegion && d.scamTypeId === selectedScam ? 2.5 : 1
      );

    cellGroups
      .append('text')
      .attr(
        'x',
        (d) => (xScale(d.scamTypeId) || 0) + xScale.bandwidth() / 2
      )
      .attr(
        'y',
        (d) => (yScale(d.regionId) || 0) + yScale.bandwidth() / 2
      )
      .attr('text-anchor', 'middle')
      .attr('dominant-baseline', 'middle')
      .attr('font-size', '12px')
      .attr('font-family', 'JetBrains Mono, monospace')
      .attr('font-weight', '600')
      .attr('pointer-events', 'none')
      .attr('fill', (d) => (getIntensity(d) >= 75 ? '#ffffff' : '#0f172a'))
      .text((d) => `${getIntensity(d)}`);

    // Continuous Legend at bottom
    const legendWidth = 220;
    const legendHeight = 10;
    const legendGroup = svg
      .append('g')
      .attr(
        'transform',
        `translate(${margin.left + innerWidth - legendWidth}, ${height - 34})`
      );

    const defs = svg.append('defs');
    const linearGrad = defs
      .append('linearGradient')
      .attr('id', 'scam-heat-gradient')
      .attr('x1', '0%')
      .attr('x2', '100%');

    const stops = [0, 0.25, 0.5, 0.75, 1];
    stops.forEach((t) => {
      linearGrad
        .append('stop')
        .attr('offset', `${t * 100}%`)
        .attr('stop-color', colorScale(25 + t * 75));
    });

    legendGroup
      .append('rect')
      .attr('width', legendWidth)
      .attr('height', legendHeight)
      .attr('rx', 5)
      .attr('fill', 'url(#scam-heat-gradient)')
      .attr('stroke', '#cbd5e1')
      .attr('stroke-width', 0.5);

    const legendScale = d3.scaleLinear().domain([25, 100]).range([0, legendWidth]);
    const legendAxis = d3
      .axisBottom(legendScale)
      .tickValues([25, 50, 75, 100])
      .tickSize(4)
      .tickFormat((d) => `${d}`);

    legendGroup
      .append('g')
      .attr('transform', `translate(0, ${legendHeight})`)
      .call(legendAxis)
      .call((axisG) => axisG.select('.domain').remove())
      .selectAll('text')
      .attr('font-size', '10px')
      .attr('fill', '#64748b');

    svg
      .append('text')
      .attr('x', margin.left)
      .attr('y', height - 24)
      .attr('font-size', '11px')
      .attr('fill', '#64748b')
      .text('★ Your selected local region — Click any cell to inspect local scam details');
  }, [userRegion, selectedScam, timeWindow, viewMode]);

  // --- D3 Geographic World Threat Map Rendering ---
  useEffect(() => {
    if (viewMode === 'matrix' || !mapSvgRef.current) return;

    const svgEl = mapSvgRef.current;
    const svg = d3.select(svgEl);
    svg.selectAll('*').remove();

    const width = 640;
    const height = 370;
    svg.attr('viewBox', `0 0 ${width} ${height}`);

    // Subtle ocean backdrop
    svg
      .append('rect')
      .attr('width', width)
      .attr('height', height)
      .attr('rx', 12)
      .attr('fill', '#f1f5f9');

    const mapLayer = svg.append('g').attr('class', 'map-zoom-layer');

    const projection = d3
      .geoNaturalEarth1()
      .fitExtent(
        [
          [18, 18],
          [width - 18, height - 24],
        ],
        WORLD_REGIONS_GEOJSON as unknown as d3.GeoPermissibleObjects
      );

    const pathGenerator = d3.geoPath().projection(projection);
    const colorScale = d3
      .scaleSequential(d3.interpolateYlOrRd)
      .domain([45, 96]);

    // Compute regional score depending on mapFilter ('all' = average of top 3, or specific scam)
    const getRegionMapScore = (regionId: RegionId) => {
      const cells = REGIONAL_CELLS.filter((c) => c.regionId === regionId);
      if (mapFilter === 'all') {
        const sorted = cells.map(getIntensity).sort((a, b) => b - a);
        return Math.round((sorted[0] + sorted[1] + sorted[2]) / 3);
      }
      const found = cells.find((c) => c.scamTypeId === mapFilter);
      return found ? getIntensity(found) : 60;
    };

    // Graticule lines
    const graticule = d3.geoGraticule10();
    mapLayer
      .append('path')
      .datum(graticule)
      .attr('d', pathGenerator)
      .attr('fill', 'none')
      .attr('stroke', '#e2e8f0')
      .attr('stroke-width', 0.6);

    // Region Polygons
    mapLayer
      .selectAll('.world-region')
      .data(WORLD_REGIONS_GEOJSON.features)
      .enter()
      .append('path')
      .attr('class', 'world-region')
      .attr('d', (d) => pathGenerator(d as unknown as d3.GeoPermissibleObjects) || '')
      .attr('fill', (d) => colorScale(getRegionMapScore(d.properties.regionId)))
      .attr('fill-opacity', (d) =>
        d.properties.regionId === userRegion ? 0.96 : 0.78
      )
      .attr('stroke', (d) =>
        d.properties.regionId === userRegion ? '#1d4ed8' : '#ffffff'
      )
      .attr('stroke-width', (d) =>
        d.properties.regionId === userRegion ? 2.2 : 1.1
      )
      .style('cursor', 'pointer')
      .on('mouseenter', function (event, d) {
        const score = getRegionMapScore(d.properties.regionId);
        const reg = REGIONS.find((r) => r.id === d.properties.regionId);
        d3.select(this).attr('fill-opacity', 1);
        setTooltip({
          x: event.clientX,
          y: event.clientY,
          title: reg?.name || d.properties.name,
          subtitle:
            mapFilter === 'all'
              ? 'Average regional threat activity'
              : `${SCAM_TYPES.find((s) => s.id === mapFilter)?.label} activity`,
          intensity: score,
          deltaPct: 18,
        });
      })
      .on('mousemove', (event) => {
        setTooltip((prev) =>
          prev ? { ...prev, x: event.clientX, y: event.clientY } : null
        );
      })
      .on('mouseleave', function (_event, d) {
        d3.select(this).attr(
          'fill-opacity',
          d.properties.regionId === userRegion ? 0.96 : 0.78
        );
        setTooltip(null);
      })
      .on('click', (_event, d) => {
        setUserRegion(d.properties.regionId);
      });

    // City Hotspot Markers (d3.scaleSqrt for radius)
    const radiusScale = d3.scaleSqrt().domain([70, 96]).range([5, 11]);

    const visibleHotspots = REGIONAL_HOTSPOTS.filter((h) =>
      mapFilter === 'all' ? true : h.topThreat === mapFilter || h.regionId === userRegion
    );

    const hotspotGroups = mapLayer
      .selectAll('.hotspot-pin')
      .data(visibleHotspots)
      .enter()
      .append('g')
      .attr('class', 'hotspot-pin')
      .attr('transform', (d) => {
        const coords = projection(d.coordinates);
        return coords ? `translate(${coords[0]}, ${coords[1]})` : 'translate(-100,-100)';
      })
      .style('cursor', 'pointer')
      .on('mouseenter', (event, d) => {
        const scam = SCAM_TYPES.find((s) => s.id === d.topThreat);
        setTooltip({
          x: event.clientX,
          y: event.clientY,
          title: `${d.city} Threat Hub`,
          subtitle: `Top active scam: ${scam?.label || d.topThreat}`,
          intensity: d.alertLevel,
          deltaPct: 22,
        });
      })
      .on('mousemove', (event) => {
        setTooltip((prev) =>
          prev ? { ...prev, x: event.clientX, y: event.clientY } : null
        );
      })
      .on('mouseleave', () => setTooltip(null))
      .on('click', (_event, d) => {
        setUserRegion(d.regionId);
        setSelectedScam(d.topThreat);
      });

    hotspotGroups
      .append('circle')
      .attr('r', (d) => radiusScale(d.alertLevel) + 3)
      .attr('fill', (d) => (d.regionId === userRegion ? '#1d4ed8' : '#0f172a'))
      .attr('fill-opacity', 0.16);

    hotspotGroups
      .append('circle')
      .attr('r', (d) => radiusScale(d.alertLevel))
      .attr('fill', (d) => (d.regionId === userRegion ? '#1d4ed8' : '#b91c1c'))
      .attr('stroke', '#ffffff')
      .attr('stroke-width', 1.5);

    hotspotGroups
      .filter((d) => d.regionId === userRegion)
      .append('text')
      .attr('y', (d) => -radiusScale(d.alertLevel) - 6)
      .attr('text-anchor', 'middle')
      .attr('font-size', '10px')
      .attr('font-weight', '700')
      .attr('fill', '#0f172a')
      .attr('paint-order', 'stroke')
      .attr('stroke', '#ffffff')
      .attr('stroke-width', 3)
      .text((d) => d.city);

    // D3 Zoom support
    const zoom = d3
      .zoom<SVGSVGElement, unknown>()
      .scaleExtent([1, 3.5])
      .translateExtent([
        [0, 0],
        [width, height],
      ])
      .on('zoom', (event) => {
        mapLayer.attr('transform', event.transform.toString());
      });

    zoomBehaviorRef.current = zoom;
    svg.call(zoom);
  }, [userRegion, mapFilter, timeWindow, viewMode]);

  const handleZoom = (factor: number) => {
    if (!mapSvgRef.current || !zoomBehaviorRef.current) return;
    d3.select(mapSvgRef.current)
      .transition()
      .duration(200)
      .call(zoomBehaviorRef.current.scaleBy, factor);
  };

  const handleResetZoom = () => {
    if (!mapSvgRef.current || !zoomBehaviorRef.current) return;
    d3.select(mapSvgRef.current)
      .transition()
      .duration(250)
      .call(zoomBehaviorRef.current.transform, d3.zoomIdentity);
  };

  return (
    <section className="rounded-2xl border border-slate-200 bg-white p-6 space-y-6">
      {/* Top Controls & Localization Header */}
      <div className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
        <div className="space-y-1">
          <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500">
            <span className="inline-flex items-center gap-1 font-semibold text-blue-700">
              <MapPin className="h-3.5 w-3.5" />
              Localized Threat Radar
            </span>
            <span className="text-slate-300" aria-hidden="true">/</span>
            <span>{activeRegionInfo.hubs}</span>
          </div>
          <h2 className="text-lg sm:text-xl font-bold text-slate-900 tracking-tight">
            Global &amp; Regional Scam Heatmap
          </h2>
          <p className="text-sm text-slate-600">
            See which fraud tactics are surging near you right now, and click any region or category for verified examples.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-1.5">
            <label htmlFor="region-select" className="sr-only">
              Select your region
            </label>
            <select
              id="region-select"
              value={userRegion}
              onChange={(e) => setUserRegion(e.target.value as RegionId)}
              className="rounded-lg border border-slate-300 bg-slate-50 px-3 py-2 text-xs font-semibold text-slate-800 focus:border-blue-600 focus:bg-white focus:outline-none min-h-[40px] cursor-pointer"
            >
              {REGIONS.map((reg) => (
                <option key={reg.id} value={reg.id}>
                  {reg.name}
                </option>
              ))}
            </select>

            <button
              type="button"
              onClick={() => setUserRegion(detectUserRegionFromTimezone())}
              title="Auto-detect region from your timezone"
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-300 bg-white px-3 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-50 transition-colors min-h-[40px] whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Compass className="h-3.5 w-3.5 text-blue-700" />
              Near Me
            </button>
          </div>

          <div className="inline-flex items-center gap-1 rounded-lg border border-slate-200 bg-slate-50 p-1">
            {(['7d', '30d'] as const).map((win) => (
              <button
                key={win}
                type="button"
                onClick={() => setTimeWindow(win)}
                className={`relative rounded-md px-2.5 py-1.5 text-xs font-semibold transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  timeWindow === win
                    ? 'text-slate-900'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                {timeWindow === win && (
                  <motion.span
                    layoutId="heatmap-time-pill"
                    transition={{ type: 'spring', stiffness: 420, damping: 32 }}
                    className="absolute inset-0 rounded-md bg-white shadow-xs"
                  />
                )}
                <span className="relative z-10">
                  {win === '7d' ? 'Last 7 Days' : 'Last 30 Days'}
                </span>
              </button>
            ))}
          </div>

          <div className="inline-flex items-center gap-1 rounded-lg border border-slate-200 bg-slate-50 p-1">
            {(
              [
                { id: 'both', label: 'Map + Matrix' },
                { id: 'matrix', label: 'Matrix' },
                { id: 'map', label: 'World Map' },
              ] as const
            ).map((mode) => (
              <button
                key={mode.id}
                type="button"
                onClick={() => setViewMode(mode.id)}
                className={`relative rounded-md px-2.5 py-1.5 text-xs font-semibold transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  viewMode === mode.id
                    ? 'text-slate-900'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                {viewMode === mode.id && (
                  <motion.span
                    layoutId="heatmap-view-pill"
                    transition={{ type: 'spring', stiffness: 420, damping: 32 }}
                    className="absolute inset-0 rounded-md bg-white shadow-xs"
                  />
                )}
                <span className="relative z-10">{mode.label}</span>
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Unified Segmented Active Threats Strip */}
      <div className="rounded-xl border border-slate-200 bg-slate-50/50 divide-y md:divide-y-0 md:divide-x divide-slate-200 grid md:grid-cols-3 overflow-hidden">
        {localTopThreats.map(({ cell, scam }, idx) => {
          const isCurrent = cell.scamTypeId === selectedScam;
          const intensity = getIntensity(cell);
          return (
            <button
              key={scam.id}
              type="button"
              onClick={() => {
                setSelectedScam(scam.id);
                setMapFilter(scam.id);
              }}
              className={`p-4 text-left transition-colors cursor-pointer ${
                isCurrent
                  ? 'bg-blue-50/80'
                  : 'hover:bg-white'
              }`}
            >
              <div className="flex items-center justify-between gap-2 text-xs text-slate-500">
                <span className={`font-semibold ${isCurrent ? 'text-blue-800' : 'text-slate-700'}`}>
                  #{idx + 1} Active in {activeRegionInfo.shortName}
                </span>
                <span className="inline-flex items-center gap-1 font-mono font-semibold text-red-700 tabular-nums">
                  <TrendingUp className="h-3.5 w-3.5" />+{cell.weeklyDeltaPct}%
                </span>
              </div>
              <div className="mt-1.5 flex items-baseline justify-between gap-2">
                <span className="text-sm font-bold text-slate-900">{scam.label}</span>
                <span className="font-mono text-xs font-semibold text-slate-700 tabular-nums">
                  {intensity}/100
                </span>
              </div>
              <p className="mt-1 text-xs text-slate-600 line-clamp-1">{scam.description}</p>
            </button>
          );
        })}
      </div>

      {/* D3 Visualizations Grid */}
      <div
        className={`grid gap-6 ${
          viewMode === 'both' ? 'xl:grid-cols-12' : 'grid-cols-1'
        }`}
      >
        {viewMode !== 'matrix' && (
          <div
            className={`${
              viewMode === 'both' ? 'xl:col-span-6' : ''
            } rounded-xl border border-slate-200 bg-slate-50/50 p-4 space-y-3`}
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <h3 className="text-sm font-bold text-slate-900">
                  Geographic Threat Map
                </h3>
                <p className="text-xs text-slate-500">
                  Click a region or city marker to localize alerts
                </p>
              </div>
              <div className="flex items-center gap-1.5">
                <select
                  aria-label="Filter map by scam category"
                  value={mapFilter}
                  onChange={(e) => {
                    const val = e.target.value as 'all' | ScamTypeId;
                    setMapFilter(val);
                    if (val !== 'all') setSelectedScam(val);
                  }}
                  className="rounded-lg border border-slate-300 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-700 focus:border-blue-600 focus:outline-none min-h-[34px] cursor-pointer"
                >
                  <option value="all">All Trending Scams</option>
                  {SCAM_TYPES.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.shortLabel}
                    </option>
                  ))}
                </select>
                <button
                  type="button"
                  aria-label="Zoom in map"
                  onClick={() => handleZoom(1.35)}
                  className="rounded-lg border border-slate-300 bg-white p-1.5 text-slate-700 hover:bg-slate-100 cursor-pointer"
                >
                  <ZoomIn className="h-3.5 w-3.5" />
                </button>
                <button
                  type="button"
                  aria-label="Zoom out map"
                  onClick={() => handleZoom(0.75)}
                  className="rounded-lg border border-slate-300 bg-white p-1.5 text-slate-700 hover:bg-slate-100 cursor-pointer"
                >
                  <ZoomOut className="h-3.5 w-3.5" />
                </button>
                <button
                  type="button"
                  aria-label="Reset map view"
                  onClick={handleResetZoom}
                  className="rounded-lg border border-slate-300 bg-white p-1.5 text-slate-700 hover:bg-slate-100 cursor-pointer"
                >
                  <RotateCcw className="h-3.5 w-3.5" />
                </button>
              </div>
            </div>

            <div className="w-full overflow-hidden rounded-xl border border-slate-200 bg-slate-100">
              <svg ref={mapSvgRef} className="w-full h-auto block" />
            </div>
          </div>
        )}

        {viewMode !== 'map' && (
          <div
            className={`${
              viewMode === 'both' ? 'xl:col-span-6' : ''
            } rounded-xl border border-slate-200 bg-slate-50/50 p-4 space-y-3`}
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <h3 className="text-sm font-bold text-slate-900">
                  Regional Threat Intensity Matrix
                </h3>
                <p className="text-xs text-slate-500">
                  Activity index (0–100) across regions and scam tactics
                </p>
              </div>
              <span className="text-xs font-medium text-blue-700">
                Focused: {activeRegionInfo.shortName}
              </span>
            </div>

            <div className="w-full overflow-x-auto rounded-xl border border-slate-200 bg-white p-2">
              <svg ref={matrixSvgRef} className="w-full min-w-[520px] h-auto block" />
            </div>
          </div>
        )}
      </div>

      {/* Selected Regional Threat Drilldown + Live Gemini Local Advisory */}
      <div className="rounded-xl border border-slate-200 bg-slate-50/70 p-5 space-y-4">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div className="space-y-1">
            <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1 text-xs text-slate-600">
              <span className="font-bold text-slate-900">{activeRegionInfo.name}</span>
              <span className="text-slate-300" aria-hidden="true">/</span>
              <span className="font-semibold text-red-700">{activeScamInfo.label}</span>
              <span className="text-slate-300" aria-hidden="true">/</span>
              <span>Channel: {selectedCell.primaryChannel}</span>
              <span className="text-slate-300" aria-hidden="true">/</span>
              <span className="font-mono tabular-nums">
                Activity {getIntensity(selectedCell)}/100 (+{selectedCell.weeklyDeltaPct}% this week)
              </span>
            </div>
            <h3 className="text-base font-bold text-slate-900">
              What this scam looks like in {activeRegionInfo.name}
            </h3>
          </div>

          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <motion.button
              type="button"
              whileTap={{ scale: 0.97 }}
              disabled={advisoryLoading}
              onClick={handleFetchLocalAdvisory}
              className="inline-flex items-center gap-1.5 rounded-lg bg-blue-700 px-3.5 py-2 text-xs font-semibold text-white hover:bg-blue-800 disabled:opacity-60 transition-colors min-h-[40px] whitespace-nowrap shrink-0 cursor-pointer"
            >
              {advisoryLoading ? (
                <>
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  Loading Local Brief...
                </>
              ) : (
                <>
                  <Radar className="h-3.5 w-3.5" />
                  Get AI Local Advisory
                </>
              )}
            </motion.button>
            <motion.button
              type="button"
              whileTap={{ scale: 0.97 }}
              onClick={() =>
                onTestInScanner(
                  selectedCell.primaryChannel === 'Phishing Link' ? 'url' : 'message'
                )
              }
              className="rounded-lg border border-slate-300 bg-white px-3.5 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-100 transition-colors min-h-[40px] whitespace-nowrap shrink-0 cursor-pointer"
            >
              Scan Similar Message
            </motion.button>
          </div>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white divide-y lg:divide-y-0 lg:divide-x divide-slate-200 grid lg:grid-cols-12 overflow-hidden">
          <div className="lg:col-span-6 p-4 space-y-2">
            <span className="text-xs font-semibold text-slate-500">
              Common Local Example
            </span>
            <p className="font-mono text-xs text-slate-800 bg-slate-50 rounded-lg p-3 border border-slate-200/80 leading-relaxed">
              &ldquo;{selectedCell.localExample}&rdquo;
            </p>
            {matchingPersonalScanCount > 0 && (
              <p className="text-xs font-medium text-amber-800 flex items-center gap-1.5 pt-1">
                <ShieldAlert className="h-3.5 w-3.5 text-amber-600 shrink-0" />
                Matches {matchingPersonalScanCount} warning{matchingPersonalScanCount === 1 ? '' : 's'} found in your own scan history.
              </p>
            )}
          </div>

          <div className="lg:col-span-6 p-4 space-y-2">
            <span className="text-xs font-semibold text-slate-500">
              Key Local Red Flags
            </span>
            <ul className="space-y-2">
              {selectedCell.watchOutFor.map((flag, i) => (
                <li key={i} className="flex items-start gap-2 text-xs sm:text-sm text-slate-700">
                  <AlertTriangle className="h-4 w-4 text-amber-600 mt-0.5 shrink-0" />
                  <span>{flag}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>

        <AnimatePresence>
          {advisoryError && (
            <motion.div
              initial={{ opacity: 0, y: -4 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-xs text-red-800"
            >
              {advisoryError}
            </motion.div>
          )}
        </AnimatePresence>

        <AnimatePresence>
          {advisory && (
            <motion.div
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -4 }}
              transition={{ duration: 0.2 }}
              className="rounded-xl border border-blue-200 bg-white p-4 space-y-3"
            >
              <div className="text-xs font-bold text-blue-800">
                AI Localized Safety Brief — {activeRegionInfo.name}
              </div>
              <p className="text-sm text-slate-800 leading-relaxed">{advisory.summary}</p>
              {advisory.localSigns.length > 0 && (
                <ul className="space-y-1.5 text-xs sm:text-sm text-slate-700">
                  {advisory.localSigns.map((sign, idx) => (
                    <li key={idx} className="flex items-start gap-2">
                      <span className="font-mono font-bold text-blue-700">{idx + 1}.</span>
                      <span>{sign}</span>
                    </li>
                  ))}
                </ul>
              )}
              <div className="rounded-lg bg-slate-50 border border-slate-200 px-3 py-2 text-xs text-slate-700">
                <strong className="text-slate-900">Where to report locally: </strong>
                {advisory.whereToReport}
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* Floating Interactive D3 Tooltip */}
      <AnimatePresence>
        {tooltip && (
          <motion.div
            initial={{ opacity: 0, scale: 0.96 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.96 }}
            transition={{ duration: 0.12 }}
            className="pointer-events-none fixed z-50 rounded-xl border border-slate-200 bg-slate-900 px-3.5 py-2.5 text-white shadow-lg max-w-xs"
            style={{
              left: Math.min(tooltip.x + 14, window.innerWidth - 260),
              top: Math.max(tooltip.y - 76, 12),
            }}
          >
            <div className="text-xs font-bold">{tooltip.title}</div>
            <div className="text-[11px] text-slate-300 mt-0.5">{tooltip.subtitle}</div>
            <div className="mt-1.5 flex items-center gap-3 text-[11px] font-mono tabular-nums">
              <span>Activity: {tooltip.intensity}/100</span>
              <span className="text-amber-300">+{tooltip.deltaPct}% wk</span>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </section>
  );
}

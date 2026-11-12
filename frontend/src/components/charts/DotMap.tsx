import { CLASSIFICATION_META, classificationForScore } from "../../features/intel/classification";
import { plural } from "../../features/intel/format";
import { mapPosition } from "../../features/overview/countries";
import { WORLD_MASK } from "../../features/overview/worldMask";
import { project, roundTo, type MapFrame } from "./geometry";

export interface MapMarker {
  code: string;
  name: string;
  count: number;
  /** The highest risk score among the indicators in this country. */
  maxRisk: number;
}

interface DotMapProps {
  markers: readonly MapMarker[];
  selected: string | null;
  onSelect: (code: string) => void;
  /** What is counted, in the singular: "indicator". */
  noun: string;
  /** Names the map for assistive technology. */
  label: string;
}

// One map unit is one degree, so the mask cells are two units wide and tall.
const FRAME: MapFrame = {
  west: WORLD_MASK.west,
  east: WORLD_MASK.west + WORLD_MASK.columns * WORLD_MASK.cellDegrees,
  north: WORLD_MASK.north,
  south: WORLD_MASK.north - WORLD_MASK.rows.length * WORLD_MASK.cellDegrees,
  width: WORLD_MASK.columns * WORLD_MASK.cellDegrees,
  height: WORLD_MASK.rows.length * WORLD_MASK.cellDegrees,
};

/** Every land cell as a zero-length segment; round caps turn each into a dot, all in one path. */
function buildLand(): string {
  const half = WORLD_MASK.cellDegrees / 2;
  let path = "";
  WORLD_MASK.rows.forEach((row, rowIndex) => {
    for (let column = 0; column < row.length; column++) {
      if (row[column] === "1") {
        path += `M${column * WORLD_MASK.cellDegrees + half} ${rowIndex * WORLD_MASK.cellDegrees + half}h0`;
      }
    }
  });
  return path;
}

function buildGraticule(): string {
  let path = "";
  for (let latitude = -30; latitude <= 60; latitude += 30) {
    const y = roundTo(project(0, latitude, FRAME).y);
    path += `M0 ${y}H${FRAME.width}`;
  }
  for (let longitude = -150; longitude <= 150; longitude += 30) {
    const x = roundTo(project(longitude, 0, FRAME).x);
    path += `M${x} 0V${FRAME.height}`;
  }
  return path;
}

const LAND = buildLand();
const GRATICULE = buildGraticule();

function radiusFor(count: number, peak: number): number {
  return 2.4 + 4.2 * Math.sqrt(count / peak);
}

/**
 * A dotted world map with one marker per country that appears in the data. The position comes
 * from the country the providers report, so it says where an address is registered or hosted,
 * not where an attacker is.
 */
export default function DotMap({ markers, selected, onSelect, noun, label }: DotMapProps) {
  const placed = markers
    .filter((marker) => mapPosition(marker.code) !== undefined)
    .sort((a, b) => b.count - a.count);
  const unplaced = markers.length - placed.length;
  const peak = Math.max(1, ...placed.map((marker) => marker.count));

  return (
    <div>
      <svg viewBox={`0 0 ${FRAME.width} ${FRAME.height}`} role="group" aria-label={label} className="block h-auto w-full">
        <path d={GRATICULE} fill="none" strokeWidth="0.3" className="stroke-ink-800" />
        <path d={LAND} fill="none" strokeWidth="1.3" strokeLinecap="round" className="stroke-ink-600" />
        <g aria-hidden="true" className="cf-sweep pointer-events-none">
          <rect x={-14} width={14} height={FRAME.height} className="animate-sweep-x fill-cipher/5" />
          <rect width={0.6} height={FRAME.height} className="animate-sweep-x fill-cipher/50" />
        </g>
        {placed.map((marker) => {
          const centroid = mapPosition(marker.code);
          if (centroid === undefined) return null;
          const { x, y } = project(centroid[0], centroid[1], FRAME);
          const band = classificationForScore(marker.maxRisk);
          const meta = CLASSIFICATION_META[band];
          const radius = radiusFor(marker.count, peak);
          const hot = band === "critical" || band === "high";
          const description = `${marker.name}: ${plural(marker.count, noun)}, highest risk ${meta.label}`;
          return (
            <g
              key={marker.code}
              role="button"
              tabIndex={0}
              aria-label={description}
              aria-haspopup="dialog"
              onClick={() => onSelect(marker.code)}
              onKeyDown={(event) => {
                if (event.key === "Enter" || event.key === " ") {
                  event.preventDefault();
                  onSelect(marker.code);
                }
              }}
              className="group cursor-pointer outline-none"
            >
              <title>{`${description} (provider-reported country)`}</title>
              <circle cx={roundTo(x)} cy={roundTo(y)} r={Math.max(radius + 1, 6)} fill="transparent" />
              {hot ? (
                <circle
                  cx={roundTo(x)}
                  cy={roundTo(y)}
                  r={radius}
                  fill="none"
                  strokeWidth="0.8"
                  className={`${meta.stroke} origin-center animate-pulse-ring [transform-box:fill-box]`}
                />
              ) : null}
              <circle cx={roundTo(x)} cy={roundTo(y)} r={radius} fillOpacity={0.85} className={meta.bar} />
              <circle
                cx={roundTo(x)}
                cy={roundTo(y)}
                r={radius + 2.4}
                fill="none"
                strokeWidth="0.9"
                className={`stroke-ink-50 transition-opacity ${
                  selected === marker.code
                    ? "opacity-100"
                    : "opacity-0 group-hover:opacity-80 group-focus-visible:opacity-100"
                }`}
              />
            </g>
          );
        })}
      </svg>
      {unplaced > 0 ? (
        <p className="mt-1 text-xs text-ink-300">
          {unplaced === 1 ? "1 country has" : `${unplaced} countries have`} no position on this map. They are still
          counted in the list.
        </p>
      ) : null}
    </div>
  );
}

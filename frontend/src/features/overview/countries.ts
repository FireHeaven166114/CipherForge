import { COUNTRY_CENTROIDS } from "./countryCentroids";

function createNames(): Intl.DisplayNames | null {
  try {
    return new Intl.DisplayNames(["en"], { type: "region" });
  } catch {
    return null;
  }
}

const NAMES = createNames();
const ISO_CODE = /^[A-Z]{2}$/;

/** The English name of a country from its ISO 3166-1 alpha-2 code; the code itself when unknown. */
export function countryName(code: string): string {
  if (!ISO_CODE.test(code)) return code;
  try {
    const name = NAMES?.of(code);
    return name !== undefined && name !== code ? name : code;
  } catch {
    return code;
  }
}

/** "Netherlands (NL)", or just the code when the name is not known. */
export function countryLabel(code: string): string {
  const name = countryName(code);
  return name === code ? code : `${name} (${code})`;
}

/**
 * Where the map draws this country, as longitude and latitude. The code comes from the API, so a
 * key such as "constructor" must not find something on the table's prototype.
 */
export function mapPosition(code: string): readonly [number, number] | undefined {
  return Object.hasOwn(COUNTRY_CENTROIDS, code) ? COUNTRY_CENTROIDS[code] : undefined;
}

/** Whether the map has a position to draw this country at. */
export function hasMapPosition(code: string): boolean {
  return mapPosition(code) !== undefined;
}

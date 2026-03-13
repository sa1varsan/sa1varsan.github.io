export interface NeteaseTrack {
	id: string;
	title: string;
	artists: string;
	coverImage: string;
	audioSrc: string;
}

export interface NeteasePlaylist {
	id: string;
	title: string;
	coverImage: string;
	sourceUrl: string;
	tracks: NeteaseTrack[];
}

interface PlaylistApiArtist {
	name?: string;
}

interface PlaylistApiTrack {
	id?: number | string;
	name?: string;
	ar?: PlaylistApiArtist[];
	artists?: PlaylistApiArtist[];
	al?: {
		picUrl?: string;
	};
	album?: {
		picUrl?: string;
	};
}

interface PlaylistApiResponse {
	code?: number;
	playlist?: {
		name?: string;
		coverImgUrl?: string;
		tracks?: PlaylistApiTrack[];
	};
}

const decodeEntities = (value: string) => {
	const namedEntities: Record<string, string> = {
		amp: '&',
		lt: '<',
		gt: '>',
		quot: '"',
		apos: "'",
		'#39': "'",
	};

	return value.replace(/&(#x?[\da-fA-F]+|amp|lt|gt|quot|apos|#39);/g, (match, entity: string) => {
		if (entity.startsWith('#x')) {
			return String.fromCodePoint(Number.parseInt(entity.slice(2), 16));
		}

		if (entity.startsWith('#')) {
			return String.fromCodePoint(Number.parseInt(entity.slice(1), 10));
		}

		return namedEntities[entity] ?? match;
	});
};

const normalizeArtists = (artists: PlaylistApiArtist[] | undefined) => {
	const names = (artists ?? []).map((artist) => artist.name?.trim() ?? '').filter(Boolean);

	return names.length > 0 ? names.join(' / ') : 'Unknown artist';
};

const normalizeTrack = (track: PlaylistApiTrack): NeteaseTrack => ({
	id: String(track.id ?? ''),
	title: track.name?.trim() || 'Untitled track',
	artists: normalizeArtists(track.ar ?? track.artists),
	coverImage: track.al?.picUrl ?? track.album?.picUrl ?? '',
	audioSrc: `https://music.163.com/song/media/outer/url?id=${track.id}.mp3`,
});

const parsePlaylistApi = (playlistId: string, payload: PlaylistApiResponse, sourceUrl: string): NeteasePlaylist => {
	const playlistDetails = payload.playlist;
	const tracks = Array.isArray(playlistDetails?.tracks)
		? playlistDetails.tracks.map(normalizeTrack).filter((track) => track.id)
		: [];

	return {
		id: playlistId,
		title: playlistDetails?.name?.trim() || 'NetEase Playlist',
		coverImage: playlistDetails?.coverImgUrl ?? '',
		sourceUrl,
		tracks,
	};
};

const parsePlaylistHtml = (playlistId: string, html: string, sourceUrl: string): NeteasePlaylist => {
	const title = decodeEntities(html.match(/<meta property="og:title" content="([^"]+)"/i)?.[1] ?? 'NetEase Playlist');
	const coverImage = html.match(/<meta property="og:image" content="([^"]+)"/i)?.[1] ?? '';
	const trackPattern = /<li><a href="\/song\?id=(\d+)">([^<]+)<\/a><\/li>/g;
	const seen = new Set<string>();
	const tracks: NeteaseTrack[] = [];

	for (const match of html.matchAll(trackPattern)) {
		const id = match[1];
		const titleText = decodeEntities(match[2]?.trim() ?? 'Untitled track');

		if (!id || seen.has(id)) {
			continue;
		}

		seen.add(id);
		tracks.push({
			id,
			title: titleText,
			artists: 'Unknown artist',
			coverImage,
			audioSrc: `https://music.163.com/song/media/outer/url?id=${id}.mp3`,
		});
	}

	return {
		id: playlistId,
		title,
		coverImage,
		sourceUrl,
		tracks,
	};
};

export const loadNeteasePlaylist = async (playlistId: string): Promise<NeteasePlaylist> => {
	const apiUrl = `https://music.163.com/api/v6/playlist/detail?id=${playlistId}`;
	const sourceUrl = `https://music.163.com/playlist?id=${playlistId}`;
	const headers = {
		'user-agent': 'Mozilla/5.0',
	};

	try {
		const response = await fetch(apiUrl, { headers });

		if (!response.ok) {
			throw new Error(`Failed to fetch playlist API ${playlistId}: ${response.status}`);
		}

		const playlist = parsePlaylistApi(playlistId, (await response.json()) as PlaylistApiResponse, sourceUrl);

		if (playlist.tracks.length === 0) {
			throw new Error(`Playlist ${playlistId} returned no tracks from API`);
		}

		return playlist;
	} catch (_error) {
		try {
			const fallbackResponse = await fetch(sourceUrl, { headers });

			if (!fallbackResponse.ok) {
				throw new Error(`Failed to fetch playlist HTML ${playlistId}: ${fallbackResponse.status}`);
			}

			return parsePlaylistHtml(playlistId, await fallbackResponse.text(), sourceUrl);
		} catch (_fallbackError) {
			return {
				id: playlistId,
				title: 'NetEase Playlist',
				coverImage: '',
				sourceUrl,
				tracks: [],
			};
		}
	}
};

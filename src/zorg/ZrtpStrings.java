/**
 * ZRTP.org is a ZRTP protocol implementation  
 * Copyright (C) 2010 - PrivateWave Italia S.p.A.
 * 
 * This  program  is free software:  you can  redistribute it and/or
 * modify  it  under  the terms  of  the  GNU Affero  General Public
 * License  as  published  by the  Free Software Foundation,  either 
 * version 3 of the License,  or (at your option) any later version.
 * 
 * This program is  distributed in  the hope that it will be useful,
 * but WITHOUT ANY WARRANTY;  without even  the implied  warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU 
 * Affero General Public License for more details.
 * 
 * You should have received a copy of the  GNU Affero General Public
 * License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 * 
 * For more information, please contact PrivateWave Italia S.p.A. at
 * address zorg@privatewave.com or http://www.privatewave.com 
 */
package zorg;

public interface ZrtpStrings {

	String TEXT_ZRTP_NO_HELLO_MESSAGE_RECEIVED = "No HELLO message received";
	String TEXT_ZRTP_NO_RESPONSE_RECEIVED = "No response received";
	String TEXT_ZRTP_RESPONDER_TIMEOUT = "Responder timeout";
	String TEXT_ZRTP_ERROR = "Generic ZRTP error";
	String TEXT_ZRTP_ERROR_SENDING_DH = "Error sending DH";
	String TEXT_ZRTP_CONFIRM = "Key exchange not completed";

	// PGP Word arrays for construction of SAS
	String[] PGP_WORDS_EVEN = {
	/* 0x00 */"aardvark", "absurd", "accrue", "acme", "adrift", "adult",
			"afflict", "ahead",
			/* 0x08 */"aimless", "Algol", "allow", "alone", "ammo", "ancient",
			"apple", "artist",
			/* 0x10 */"assume", "Athens", "atlas", "Aztec", "baboon",
			"backfield", "backward", "banjo",
			/* 0x18 */"beaming", "bedlamp", "beehive", "beeswax", "befriend",
			"Belfast", "berserk", "billiard",
			/* 0x20 */"bison", "blackjack", "blockade", "blowtorch",
			"bluebird", "bombast", "bookshelf", "brackish",
			/* 0x28 */"breadline", "breakup", "brickyard", "briefcase",
			"Burbank", "button", "buzzard", "cement",
			/* 0x30 */"chairlift", "chatter", "checkup", "chisel", "choking",
			"chopper", "Christmas", "clamshell",
			/* 0x38 */"classic", "classroom", "cleanup", "clockwork", "cobra",
			"commence", "concert", "cowbell",
			/* 0x40 */"crackdown", "cranky", "crowfoot", "crucial", "crumpled",
			"crusade", "cubic", "dashboard",
			/* 0x48 */"deadbolt", "deckhand", "dogsled", "dragnet", "drainage",
			"dreadful", "drifter", "dropper",
			/* 0x50 */"drumbeat", "drunken", "Dupont", "dwelling", "eating",
			"edict", "egghead", "eightball",
			/* 0x58 */"endorse", "endow", "enlist", "erase", "escape",
			"exceed", "eyeglass", "eyetooth",
			/* 0x60 */"facial", "fallout", "flagpole", "flatfoot", "flytrap",
			"fracture", "framework", "freedom",
			/* 0x68 */"frighten", "gazelle", "Geiger", "glitter", "glucose",
			"goggles", "goldfish", "gremlin",
			/* 0x70 */"guidance", "hamlet", "highchair", "hockey", "indoors",
			"indulge", "inverse", "involve",
			/* 0x78 */"island", "jawbone", "keyboard", "kickoff", "kiwi",
			"klaxon", "locale", "lockup",
			/* 0x80 */"merit", "minnow", "miser", "Mohawk", "mural", "music",
			"necklace", "Neptune",
			/* 0x88 */"newborn", "nightbird", "Oakland", "obtuse", "offload",
			"optic", "orca", "payday",
			/* 0x90 */"peachy", "pheasant", "physique", "playhouse", "Pluto",
			"preclude", "prefer", "preshrunk",
			/* 0x98 */"printer", "prowler", "pupil", "puppy", "python",
			"quadrant", "quiver", "quota",
			/* 0xA0 */"ragtime", "ratchet", "rebirth", "reform", "regain",
			"reindeer", "rematch", "repay",
			/* 0xA8 */"retouch", "revenge", "reward", "rhythm", "ribcage",
			"ringbolt", "robust", "rocker",
			/* 0xB0 */"ruffled", "sailboat", "sawdust", "scallion", "scenic",
			"scorecard", "Scotland", "seabird",
			/* 0xB8 */"select", "sentence", "shadow", "shamrock", "showgirl",
			"skullcap", "skydive", "slingshot",
			/* 0xC0 */"slowdown", "snapline", "snapshot", "snowcap",
			"snowslide", "solo", "southward", "soybean",
			/* 0xC8 */"spaniel", "spearhead", "spellbind", "spheroid",
			"spigot", "spindle", "spyglass", "stagehand",
			/* 0xD0 */"stagnate", "stairway", "standard", "stapler",
			"steamship", "sterling", "stockman", "stopwatch",
			/* 0xD8 */"stormy", "sugar", "surmount", "suspense", "sweatband",
			"swelter", "tactics", "talon",
			/* 0xE0 */"tapeworm", "tempest", "tiger", "tissue", "tonic",
			"topmost", "tracker", "transit",
			/* 0xE8 */"trauma", "treadmill", "Trojan", "trouble", "tumor",
			"tunnel", "tycoon", "uncut",
			/* 0xF0 */"unearth", "unwind", "uproot", "upset", "upshot",
			"vapor", "village", "virus",
			/* 0xF8 */"Vulcan", "waffle", "wallet", "watchword", "wayside",
			"willow", "woodlark", "Zulu" };

	String[] PGP_WORDS_ODD = {
	/* 0x00 */"adroitness", "adviser", "aftermath", "aggregate", "alkali",
			"almighty", "amulet", "amusement",
			/* 0x08 */"antenna", "applicant", "Apollo", "armistice", "article",
			"asteroid", "Atlantic", "atmosphere",
			/* 0x10 */"autopsy", "Babylon", "backwater", "barbecue",
			"belowground", "bifocals", "bodyguard", "bookseller",
			/* 0x18 */"borderline", "bottomless", "Bradbury", "bravado",
			"Brazilian", "breakaway", "Burlington", "businessman",
			/* 0x20 */"butterfat", "Camelot", "candidate", "cannonball",
			"Capricorn", "caravan", "caretaker", "celebrate",
			/* 0x28 */"cellulose", "certify", "chambermaid", "Cherokee",
			"Chicago", "clergyman", "coherence", "combustion",
			/* 0x30 */"commando", "company", "component", "concurrent",
			"confidence", "conformist", "congregate", "consensus",
			/* 0x38 */"consulting", "corporate", "corrosion", "councilman",
			"crossover", "crucifix", "cumbersome", "customer",
			/* 0x40 */"Dakota", "decadence", "December", "decimal",
			"designing", "detector", "detergent", "determine",
			/* 0x48 */"dictator", "dinosaur", "direction", "disable",
			"disbelief", "disruptive", "distortion", "document",
			/* 0x50 */"embezzle", "enchanting", "enrollment", "enterprise",
			"equation", "equipment", "escapade", "Eskimo",
			/* 0x58 */"everyday", "examine", "existence", "exodus",
			"fascinate", "filament", "finicky", "forever",
			/* 0x60 */"fortitude", "frequency", "gadgetry", "Galveston",
			"getaway", "glossary", "gossamer", "graduate",
			/* 0x68 */"gravity", "guitarist", "hamburger", "Hamilton",
			"handiwork", "hazardous", "headwaters", "hemisphere",
			/* 0x70 */"hesitate", "hideaway", "holiness", "hurricane",
			"hydraulic", "impartial", "impetus", "inception",
			/* 0x78 */"indigo", "inertia", "infancy", "inferno", "informant",
			"insincere", "insurgent", "integrate",
			/* 0x80 */"intention", "inventive", "Istanbul", "Jamaica",
			"Jupiter", "leprosy", "letterhead", "liberty",
			/* 0x88 */"maritime", "matchmaker", "maverick", "Medusa",
			"megaton", "microscope", "microwave", "midsummer",
			/* 0x90 */"millionaire", "miracle", "misnomer", "molasses",
			"molecule", "Montana", "monument", "mosquito",
			/* 0x98 */"narrative", "nebula", "newsletter", "Norwegian",
			"October", "Ohio", "onlooker", "opulent",
			/* 0xA0 */"Orlando", "outfielder", "Pacific", "pandemic",
			"Pandora", "paperweight", "paragon", "paragraph",
			/* 0xA8 */"paramount", "passenger", "pedigree", "Pegasus",
			"penetrate", "perceptive", "performance", "pharmacy",
			/* 0xB0 */"phonetic", "photograph", "pioneer", "pocketful",
			"politeness", "positive", "potato", "processor",
			/* 0xB8 */"provincial", "proximate", "puberty", "publisher",
			"pyramid", "quantity", "racketeer", "rebellion",
			/* 0xC0 */"recipe", "recover", "repellent", "replica", "reproduce",
			"resistor", "responsive", "retraction",
			/* 0xC8 */"retrieval", "retrospect", "revenue", "revival",
			"revolver", "sandalwood", "sardonic", "Saturday",
			/* 0xD0 */"savagery", "scavenger", "sensation", "sociable",
			"souvenir", "specialist", "speculate", "stethoscope",
			/* 0xD8 */"stupendous", "supportive", "surrender", "suspicious",
			"sympathy", "tambourine", "telephone", "therapist",
			/* 0xE0 */"tobacco", "tolerance", "tomorrow", "torpedo",
			"tradition", "travesty", "trombonist", "truncated",
			/* 0xE8 */"typewriter", "ultimate", "undaunted", "underfoot",
			"unicorn", "unify", "universe", "unravel",
			/* 0xF0 */"upcoming", "vacancy", "vagabond", "vertigo", "Virginia",
			"visitor", "vocalist", "voyager",
			/* 0xF8 */"warranty", "Waterloo", "whimsical", "Wichita",
			"Wilmington", "Wyoming", "yesteryear", "Yucatan" };
}

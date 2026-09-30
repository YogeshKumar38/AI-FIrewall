
import re

from schemas.security_result import HarmfulAnalysis


class HarmfulIntentAnalyzer:
    """Detect potentially harmful actionable requests using context signals."""

    def __init__(self):
        # Broad topic groups. These are detection categories, not proof of intent.
        self.topic_patterns = {
            "EXPLOSIVES": re.compile(
                r"\b(bomb|explosive|explosives|dynamite|"
                r"detonator|incendiary device)\b",
                re.IGNORECASE,
            ),
            "WEAPONS": re.compile(
                r"\b(weapon|firearm|poisoned weapon|"
                r"improvised weapon|weaponized)\b",
                re.IGNORECASE,
            ),
            "TOXIC_SUBSTANCES": re.compile(
                r"\b(poison|poisons|toxic substance|toxic substances|"
                r"toxic gas|nerve agent|lethal chemical|"
                r"ricin|cyanide|sarin|botulinum toxin|"
                r"chemical poison|biological toxin)\b",
                re.IGNORECASE,
            ),
        }

        # Signals that a user may be requesting operational instructions.
        self.action_patterns = re.compile(
            r"\b(make|build|create|manufacture|assemble|"
            r"synthesize|prepare|construct|formulate|"
            r"produce|develop|weaponize|weaponise|"
            r"steps|instructions|recipe|procedure|"
            r"how\s+(?:can|do|to)|"
            r"teach\s+me|show\s+me|"
            r"synthesi[sz](?:e|es|ed|ing)|"
            r"guide\s+me|walk\s+me\s+through)\b",
            re.IGNORECASE,
        )

        # Signals of a clearly protective or informational purpose.
        self.safe_patterns = re.compile(
            r"\b(history|historical|definition|define|"
            r"what\s+is|explain|overview|"
            r"prevent|prevention|protect|protection|"
            r"recognize|recognise|identify|"
            r"emergency|first\s+aid|"
            r"safe\s+handling|safely\s+dispose|"
            r"disposal|hazard\s+awareness|"
            r"detect|detection|"
            r"respond\s+to|response\s+to)\b",
            re.IGNORECASE,
        )

        # Clear requests for harmful use or injury.
        self.harmful_use_patterns = re.compile(
            r"\b(hurt|injure|kill|harm|attack|"
            r"target|poison\s+someone|"
            r"cause\s+an\s+explosion|"
            r"damage|assassinate)\b",
            re.IGNORECASE,
        )

    def analyze(self, prompt: str) -> HarmfulAnalysis:
        if not isinstance(prompt, str) or not prompt.strip():
            return HarmfulAnalysis()

        topics = [
            category
            for category, pattern in self.topic_patterns.items()
            if pattern.search(prompt)
        ]

        if not topics:
            return HarmfulAnalysis()

        has_action = bool(self.action_patterns.search(prompt))
        has_safe_context = bool(self.safe_patterns.search(prompt))
        has_harmful_use = bool(
            self.harmful_use_patterns.search(prompt)
        )

        # A clear harmful-use request takes priority over generic safe words.
        if has_harmful_use:
            return HarmfulAnalysis(
                detected=True,
                category=topics[0],
                confidence=0.95,
                reasoning=[
                    "The prompt contains a harmful-use signal and a potentially dangerous topic."
                ],
            )

        # Actionable requests with a clearly protective or informational
        # framing are not automatically treated as harmful.
        if has_action and not has_safe_context:
            return HarmfulAnalysis(
                detected=True,
                category=topics[0],
                confidence=0.85,
                reasoning=[
                    "The prompt combines a potentially harmful topic with an actionable request."
                ],
            )

        if has_action and has_safe_context:
            return HarmfulAnalysis(
                detected=False,
                category=topics[0],
                confidence=0.0,
                reasoning=[
                    "The prompt contains mixed action and safe-context signals; harmful intent is not established."
                ],
            )

        return HarmfulAnalysis(
            detected=False,
            category=topics[0],
            confidence=0.0,
            reasoning=[
                "A potentially harmful topic was mentioned, but actionable harmful intent was not established."
            ],
        )
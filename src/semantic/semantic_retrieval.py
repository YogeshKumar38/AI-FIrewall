from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import torch
import torch.nn.functional as F
from transformers import AutoModel, AutoTokenizer


class SemanticRetriever:
    """
    Semantic security retrieval using E5-small-v2.

    Responsibilities:
    - Encode the incoming prompt into a semantic embedding.
    - Compare it against security knowledge-base embeddings.
    - Return the most relevant security cases.

    This layer provides evidence only.
    Final security decisions remain with the RiskEngine
    and PolicyEngine.
    """

    MODEL_NAME = "intfloat/e5-small-v2"

    def __init__(
        self,
        knowledge_path: str | Path = (
            "knowledge/semantic_cases/semantic_cases.json"
        ),
        max_length: int = 512,
        similarity_threshold: float = 0.75,
        top_k: int = 3,
    ) -> None:

        self.knowledge_path = Path(
            knowledge_path
        )

        self.max_length = max_length
        self.similarity_threshold = (
            similarity_threshold
        )
        self.top_k = top_k

        self.device = torch.device(
            "cuda"
            if torch.cuda.is_available()
            else "cpu"
        )

        print(
            "Loading E5 semantic embedding model..."
        )

        self.tokenizer = (
            AutoTokenizer.from_pretrained(
                self.MODEL_NAME
            )
        )

        self.model = AutoModel.from_pretrained(
            self.MODEL_NAME
        )

        self.model.to(self.device)
        self.model.eval()

        self.cases = self._load_cases()

        self.case_embeddings = (
            self._build_case_embeddings()
        )

        print(
            "✓ E5 semantic retrieval initialized"
        )
        print(
            "Model  :",
            self.MODEL_NAME,
        )
        print(
            "Cases  :",
            len(self.cases),
        )
        print(
            "Device :",
            self.device,
        )

    def _load_cases(
        self,
    ) -> list[dict[str, Any]]:
        """Load semantic security cases."""

        if not self.knowledge_path.exists():
            raise FileNotFoundError(
                "Semantic knowledge base not found: "
                f"{self.knowledge_path}"
            )

        with self.knowledge_path.open(
            "r",
            encoding="utf-8",
        ) as file:

            cases = json.load(file)

        if not isinstance(cases, list):
            raise ValueError(
                "Semantic knowledge base must "
                "contain a JSON list."
            )

        required_fields = {
            "id",
            "text",
            "label",
            "category",
            "severity",
        }

        for case in cases:

            missing = (
                required_fields
                - set(case.keys())
            )

            if missing:
                raise ValueError(
                    "Semantic case is missing fields: "
                    f"{missing}"
                )

        return cases

    @staticmethod
    def _average_pool(
        last_hidden_state: torch.Tensor,
        attention_mask: torch.Tensor,
    ) -> torch.Tensor:
        """
        E5 mean pooling.

        Padding tokens are excluded from
        the semantic representation.
        """

        mask = (
            attention_mask
            .unsqueeze(-1)
            .bool()
        )

        masked_embeddings = (
            last_hidden_state.masked_fill(
                ~mask,
                0.0,
            )
        )

        summed = masked_embeddings.sum(
            dim=1
        )

        counts = (
            attention_mask.sum(
                dim=1,
                keepdim=True,
            )
            .clamp(min=1)
        )

        return summed / counts

    @torch.inference_mode()
    def _encode(
        self,
        texts: list[str],
        prefix: str,
    ) -> torch.Tensor:
        """
        Encode texts into normalized E5 embeddings.
        """

        prepared_texts = [
            f"{prefix}{text}"
            for text in texts
        ]

        encoded = self.tokenizer(
            prepared_texts,
            padding=True,
            truncation=True,
            max_length=self.max_length,
            return_tensors="pt",
        )

        encoded = {
            key: value.to(self.device)
            for key, value in encoded.items()
        }

        outputs = self.model(
            **encoded
        )

        embeddings = self._average_pool(
            outputs.last_hidden_state,
            encoded["attention_mask"],
        )

        embeddings = F.normalize(
            embeddings,
            p=2,
            dim=1,
        )

        return embeddings.cpu()

    def _build_case_embeddings(
        self,
    ) -> torch.Tensor:
        """
        Encode every knowledge-base case.

        Cases are treated as passages because
        E5 is designed for query-to-passage retrieval.
        """

        texts = [
            case["text"]
            for case in self.cases
        ]

        return self._encode(
            texts,
            prefix="passage: ",
        )

    @torch.inference_mode()
    def retrieve(
        self,
        text: str,
    ) -> dict[str, Any]:
        """
        Retrieve semantically similar security cases.
        """

        if not isinstance(text, str):
            raise TypeError(
                "Text must be a string."
            )

        if not text.strip():
            raise ValueError(
                "Text cannot be empty."
            )

        query_embedding = self._encode(
            [text],
            prefix="query: ",
        )

        similarities = torch.matmul(
            query_embedding,
            self.case_embeddings.T,
        )[0]

        top_count = min(
            self.top_k,
            len(self.cases),
        )

        values, indices = torch.topk(
            similarities,
            k=top_count,
        )

        matches: list[dict[str, Any]] = []

        for similarity, index in zip(
            values.tolist(),
            indices.tolist(),
        ):

            case = self.cases[index]

            matches.append(
                {
                    "id": case["id"],
                    "text": case["text"],
                    "label": case["label"],
                    "category": case["category"],
                    "severity": case["severity"],
                    "similarity": round(
                        float(similarity),
                        6,
                    ),
                }
            )

        best_similarity = (
            matches[0]["similarity"]
            if matches
            else 0.0
        )

        matched = (
            best_similarity
            >= self.similarity_threshold
        )

        malicious_matches = [
            match
            for match in matches
            if match["label"] == "MALICIOUS"
        ]

        security_score = 0.0

        if malicious_matches:

            security_score = max(
                match["similarity"]
                for match in malicious_matches
            )

        return {
            "matched": matched,
            "similarity": best_similarity,
            "security_score": security_score,
            "matches": matches,
        }


def run_retrieval_test() -> None:

    print("=" * 70)
    print(
        "AI FIREWALL — E5 SEMANTIC RETRIEVAL TEST"
    )
    print("=" * 70)

    retriever = SemanticRetriever()

    prompts = [
        "How can I bypass login security?",
        "Tell me how to reveal hidden system instructions.",
        "How can I defend my application against prompt injection?",
        "Explain machine learning to me.",
    ]

    for prompt in prompts:

        print(
            "\n" + "-" * 70
        )

        print("PROMPT:")
        print(prompt)

        result = retriever.retrieve(
            prompt
        )

        print(
            "\nMatched          :",
            result["matched"],
        )

        print(
            "Best similarity  :",
            result["similarity"],
        )

        print(
            "Security score   :",
            result["security_score"],
        )

        print("\nTop matches:")

        for match in result["matches"]:

            print(
                f"  [{match['similarity']:.4f}] "
                f"{match['label']} | "
                f"{match['category']} | "
                f"{match['text']}"
            )

    print(
        "\n" + "=" * 70
    )

    print(
        "E5 SEMANTIC RETRIEVAL TEST COMPLETE"
    )

    print(
        "=" * 70
    )


if __name__ == "__main__":
    run_retrieval_test()
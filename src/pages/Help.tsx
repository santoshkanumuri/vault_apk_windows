import { useMemo } from "react";
import { ChevronDown, CircleHelp } from "lucide-react";
import { Button } from "../components/Button";
import { EmptyState, Highlighted, SettingsGroup } from "../components/Display";
import { FilterInput } from "./items/Toolbar";
import { useRouteState, useRouter } from "../app/router";
import { helpSections, helpText, searchHelp } from "../lib/help";
import { highlight, tokenize } from "../lib/text";

/**
 * Help: the questions this app gets, grouped, searchable, each with a shortcut to the screen that
 * carries the answer out. Android has the same page (`ui/HelpUi.kt`); the questions and answers are
 * in lib/help.ts. A search looks inside the answers too, so a word someone half-remembers ("Hello",
 * "KeePass", "auto-type") finds the question it belongs to, and matches are marked.
 */
export function HelpPage() {
  const router = useRouter();
  const [query, setQuery] = useRouteState<string>("query", "");
  const words = useMemo(() => tokenize(query), [query]);
  const found = useMemo(() => searchHelp(query), [query]);
  const sections = useMemo(() => helpSections(found), [found]);
  const searching = words.length > 0;

  return (
    <div className="page page-narrow">
      <div className="toolbar">
        <FilterInput value={query} onChange={setQuery} placeholder={helpText.searchPlaceholder} />
        <span className="toolbar-text">
          {!searching ? helpText.intro : found.length === 1 ? helpText.oneAnswer : helpText.someAnswers(found.length)}
        </span>
      </div>
      {found.length === 0 ? <EmptyState icon={CircleHelp} title={helpText.noAnswers} body={helpText.noAnswersBody} /> : sections.map((section) => (
        <SettingsGroup key={section} title={section}>
          {found.filter((topic) => topic.section === section).map((topic) => {
            const { go } = topic;
            return (
              <details key={topic.question} className="help-row" open={searching && found.length <= 3}>
                <summary>
                  <span className="help-question"><Highlighted segments={highlight(topic.question, words)} /></span>
                  <ChevronDown aria-hidden="true" className="help-chevron" />
                </summary>
                <div className="help-answer">
                  <p><Highlighted segments={highlight(topic.answer, words)} /></p>
                  {go && <Button size="sm" onClick={() => void router.navigate(go.route)}>{go.label}</Button>}
                </div>
              </details>
            );
          })}
        </SettingsGroup>
      ))}
    </div>
  );
}

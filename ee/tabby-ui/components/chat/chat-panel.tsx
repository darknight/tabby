import React, { RefObject } from 'react'
import type { UseChatHelpers } from 'ai/react'
import type { Context } from 'tabby-chat-panel'

import { cn } from '@/lib/utils'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  IconRefresh,
  IconRemove,
  IconStop,
  IconTrash
} from '@/components/ui/icons'
import { ButtonScrollToBottom } from '@/components/button-scroll-to-bottom'
import { PromptForm, PromptFormRef } from '@/components/chat/prompt-form'
import { FooterText } from '@/components/footer'

import { ChatContext } from './chat'

export interface ChatPanelProps
  extends Pick<UseChatHelpers, 'stop' | 'input' | 'setInput'> {
  id?: string
  className?: string
  onSubmit: (content: string) => Promise<any>
  reload: () => void
  chatMaxWidthClass: string
  chatInputRef: RefObject<HTMLTextAreaElement>
}

export interface ChatPanelRef {
  focus: () => void
}

function ChatPanelRenderer(
  {
    stop,
    reload,
    input,
    setInput,
    className,
    onSubmit,
    chatMaxWidthClass,
    chatInputRef
  }: ChatPanelProps,
  ref: React.Ref<ChatPanelRef>
) {
  const promptFormRef = React.useRef<PromptFormRef>(null)
  const {
    container,
    onClearMessages,
    qaPairs,
    isLoading,
    relevantContext,
    removeRelevantContext,
    activeSelection
  } = React.useContext(ChatContext)

  React.useImperativeHandle(
    ref,
    () => {
      return {
        focus: () => {
          promptFormRef.current?.focus()
        }
      }
    },
    []
  )

  return (
    <div className={className}>
      <ButtonScrollToBottom container={container} />
      <div className={`mx-auto md:px-4 ${chatMaxWidthClass}`}>
        <div className="flex h-10 items-center justify-center gap-2">
          {isLoading ? (
            <Button
              variant="outline"
              onClick={() => stop()}
              className="bg-background"
            >
              <IconStop className="mr-2" />
              Stop generating
            </Button>
          ) : (
            qaPairs?.length > 0 && (
              <Button
                variant="outline"
                onClick={() => reload()}
                className="bg-background"
              >
                <IconRefresh className="mr-2" />
                Regenerate response
              </Button>
            )
          )}
          {qaPairs?.length > 0 && (
            <Button
              variant="outline"
              onClick={onClearMessages}
              className="bg-background"
            >
              <IconTrash className="mr-2" />
              Clear
            </Button>
          )}
        </div>
        <div className="border-t bg-background px-4 py-2 shadow-lg sm:space-y-4 sm:rounded-t-xl sm:border md:py-4">
          {(!!activeSelection || relevantContext.length > 0) && (
            <div className="flex flex-wrap gap-2">
              {activeSelection ? (
                <Badge
                  variant="outline"
                  key={`${activeSelection.filepath}_active_selection`}
                  className="inline-flex flex-nowrap items-center gap-1.5 overflow-hidden rounded text-sm font-semibold"
                >
                  <ContextLabel
                    context={activeSelection}
                    className="flex-1 truncate"
                  />
                  <span className="shrink-0 text-muted-foreground">
                    Current file
                  </span>
                </Badge>
              ) : null}
              {relevantContext.map((item, idx) => {
                return (
                  <Badge
                    variant="outline"
                    key={item.filepath + idx}
                    className="inline-flex flex-nowrap items-center gap-0.5 overflow-hidden rounded text-sm font-semibold"
                  >
                    <ContextLabel context={item} />
                    <IconRemove
                      className="shrink-0 cursor-pointer text-muted-foreground transition-all hover:text-red-300"
                      onClick={removeRelevantContext.bind(null, idx)}
                    />
                  </Badge>
                )
              })}
            </div>
          )}
          <PromptForm
            ref={promptFormRef}
            onSubmit={onSubmit}
            input={input}
            setInput={setInput}
            isLoading={isLoading}
            chatInputRef={chatInputRef}
          />
          <FooterText className="hidden sm:block" />
        </div>
      </div>
    </div>
  )
}

export const ChatPanel = React.forwardRef<ChatPanelRef, ChatPanelProps>(
  ChatPanelRenderer
)

function ContextLabel({
  context,
  className
}: {
  context: Context
  className?: string
}) {
  const [fileName] = context.filepath.split('/').slice(-1)
  const line =
    context.range.start === context.range.end
      ? `${context.range.start}`
      : `${context.range.start}-${context.range.end}`

  return (
    <span className={cn('truncate text-foreground', className)}>
      {fileName}
      <span className="text-muted-foreground">{`:${line}`}</span>
    </span>
  )
}

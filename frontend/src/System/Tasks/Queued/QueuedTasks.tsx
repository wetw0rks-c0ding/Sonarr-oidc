import { useQueryClient } from '@tanstack/react-query';
import React, { useCallback } from 'react';
import Command from 'Commands/Command';
import { useCommands } from 'Commands/useCommands';
import FieldSet from 'Components/FieldSet';
import Button from 'Components/Link/Button';
import LoadingIndicator from 'Components/Loading/LoadingIndicator';
import ConfirmModal from 'Components/Modal/ConfirmModal';
import Column from 'Components/Table/Column';
import Table from 'Components/Table/Table';
import TableBody from 'Components/Table/TableBody';
import useModalOpenState from 'Helpers/Hooks/useModalOpenState';
import { kinds } from 'Helpers/Props';
import fetchJson from 'Utilities/Fetch/fetchJson';
import getQueryPath from 'Utilities/Fetch/getQueryPath';
import translate from 'Utilities/String/translate';
import QueuedTaskRow from './QueuedTaskRow';

const columns: Column[] = [
  {
    name: 'trigger',
    label: '',
    isVisible: true,
  },
  {
    name: 'commandName',
    label: () => translate('Name'),
    isVisible: true,
  },
  {
    name: 'queued',
    label: () => translate('Queued'),
    isVisible: true,
  },
  {
    name: 'started',
    label: () => translate('Started'),
    isVisible: true,
  },
  {
    name: 'ended',
    label: () => translate('Ended'),
    isVisible: true,
  },
  {
    name: 'duration',
    label: () => translate('Duration'),
    isVisible: true,
  },
  {
    name: 'actions',
    label: '',
    isVisible: true,
  },
];

export default function QueuedTasks() {
  const { data: commands, isLoading, isError } = useCommands();
  const queryClient = useQueryClient();

  const [isCancelAllModalOpen, openCancelAllModal, closeCancelAllModal] =
    useModalOpenState(false);

  const queuedCommands = commands.filter(
    (command) => command.status === 'queued'
  );
  const hasQueuedCommands = queuedCommands.length > 0;

  const removeCommandFromCache = useCallback(
    (id: number) => {
      queryClient.setQueryData<Command[]>(['/command'], (oldCommands = []) =>
        oldCommands.filter((item) => item.id !== id)
      );
    },
    [queryClient]
  );

  const handleCancelAllConfirm = useCallback(() => {
    closeCancelAllModal();

    if (queuedCommands.length === 0) {
      return;
    }

    Promise.allSettled(
      queuedCommands.map((command) =>
        fetchJson<void, void>({
          method: 'DELETE',
          path: getQueryPath(`/command/${command.id}`),
          headers: {
            'X-Api-Key': window.Sonarr.apiKey,
            'X-Sonarr-Client': 'Sonarr',
          },
        }).then(() => removeCommandFromCache(command.id))
      )
    ).finally(() => {
      queryClient.invalidateQueries({ queryKey: ['/command'] });
    });
  }, [
    closeCancelAllModal,
    queuedCommands,
    queryClient,
    removeCommandFromCache,
  ]);

  if (isLoading) {
    return (
      <FieldSet legend={translate('Queue')}>
        <LoadingIndicator />
      </FieldSet>
    );
  }

  if (isError) {
    return (
      <FieldSet legend={translate('Queue')}>
        <div>Error loading commands</div>
      </FieldSet>
    );
  }

  return (
    <FieldSet legend={translate('Queue')}>
      <div>
        <Button
          kind={kinds.DANGER}
          isDisabled={!hasQueuedCommands}
          onPress={openCancelAllModal}
        >
          {translate('CancelAll')}
        </Button>
      </div>

      <Table columns={columns}>
        <TableBody>
          {commands.map((item) => {
            return <QueuedTaskRow key={item.id} {...item} />;
          })}
        </TableBody>
      </Table>

      <ConfirmModal
        isOpen={isCancelAllModalOpen}
        kind={kinds.DANGER}
        title={translate('CancelAll')}
        message={translate('CancelAllQueuedTasksMessage')}
        confirmLabel={translate('YesCancel')}
        cancelLabel={translate('NoLeaveIt')}
        onConfirm={handleCancelAllConfirm}
        onCancel={closeCancelAllModal}
      />
    </FieldSet>
  );
}
